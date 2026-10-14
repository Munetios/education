function webFilterCssBackground(getConfig) {
  const styleJobs = new Map();
  let fontPromise;
  function applyStyle(tabId, documentId, css) {
    const pending = styleJobs.get(tabId) || Promise.resolve();
    const job = pending
      .catch(() => {})
      .then(async () => {
        if (!(await getConfig()).allowUserCss) css = "";
        const key = "user-css-applied:" + tabId;
        const saved = await chrome.storage.session.get(key),
          previous = saved[key];
        if (previous?.documentId === documentId && previous.css === css) return;
        const target = { tabId, documentIds: [documentId] };
        if (previous?.documentId === documentId && previous.css)
          await chrome.scripting.removeCSS({
            target,
            css: previous.css,
            origin: "AUTHOR",
          });
        if (css) {
          await chrome.scripting.insertCSS({ target, css, origin: "AUTHOR" });
          await chrome.storage.session.set({ [key]: { documentId, css } });
        } else await chrome.storage.session.remove(key);
      });
    styleJobs.set(tabId, job);
    return job.finally(() => {
      if (styleJobs.get(tabId) === job) styleJobs.delete(tabId);
    });
  }
  const canStyle = (value) => {
    try {
      const url = new URL(value);
      return (
        ["http:", "https:"].includes(url.protocol) &&
        !(
          url.origin === "https://education.munetios.com" &&
          /^\/block(?:\.html)?$/.test(url.pathname)
        )
      );
    } catch {
      return false;
    }
  };
  const popupUrl = chrome.runtime.getURL("customize.html");
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (
      !message?.type?.startsWith("user-css:") ||
      sender.id !== chrome.runtime.id
    )
      return;
    (async () => {
      const config = await getConfig();
      const fromPage =
        sender.tab &&
        sender.frameId === 0 &&
        typeof sender.documentId === "string" &&
        canStyle(sender.url);
      const fromPopup = sender.url === popupUrl;
      if (!fromPage && !fromPopup) throw new Error("Unavailable");
      if (message.type === "user-css:font") {
        if (!fromPage || !config.allowUserCss) throw new Error("Unavailable");
        if (!fontPromise)
          fontPromise = fetch(chrome.runtime.getURL("fonts/googlesansflex.ttf"))
            .then(async (response) => {
              if (!response.ok) throw new Error("Font unavailable");
              const bytes = new Uint8Array(await response.arrayBuffer());
              let binary = "";
              for (let offset = 0; offset < bytes.length; offset += 8192)
                binary += String.fromCharCode(
                  ...bytes.subarray(offset, offset + 8192),
                );
              return btoa(binary);
            })
            .catch((error) => {
              fontPromise = null;
              throw error;
            });
        respond({ font: await fontPromise });
        return;
      }
      if (message.type === "user-css:ready") {
        if (!fromPage) throw new Error("Unavailable");
        const origin = new URL(sender.url).origin;
        const key = "user-css:" + origin;
        const saved = await chrome.storage.local.get(key);
        await applyStyle(
          sender.tab.id,
          sender.documentId,
          config.allowUserCss ? saved[key] || "" : "",
        );
        const latest = await getConfig();
        respond({
          enabled: latest.allowUserCss === true,
          css: latest.allowUserCss ? saved[key] || "" : "",
          strings: latest.userCssStrings,
        });
        return;
      }
      if (message.type === "user-css:selected") {
        if (
          !fromPage ||
          !config.allowUserCss ||
          typeof message.selector !== "string" ||
          message.selector.length > 2048
        )
          throw new Error("Unavailable");
        await chrome.storage.session.set({
          ["user-css-selection:" + sender.tab.id]: {
            origin: new URL(sender.url).origin,
            selector: message.selector,
          },
        });
        respond({ success: true });
        return;
      }
      if (!fromPopup) throw new Error("Unavailable");
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });
      const usable = tab?.id !== undefined && canStyle(tab.url);
      const common = {
        enabled: config.allowUserCss === true,
        usable,
        strings: config.userCssStrings,
        schoolName: config.schoolName,
        locale: config.locale,
      };
      if (!usable || !config.allowUserCss) {
        respond(common);
        return;
      }
      const origin = new URL(tab.url).origin;
      const key = "user-css:" + origin,
        draftKey = "user-css-draft:" + origin,
        selectionKey = "user-css-selection:" + tab.id;
      if (message.type === "user-css:state") {
        const saved = await chrome.storage.local.get(key);
        const session = await chrome.storage.session.get([
          draftKey,
          selectionKey,
        ]);
        const selected = session[selectionKey];
        respond({
          ...common,
          origin,
          css: session[draftKey] ?? saved[key] ?? "",
          selector: selected?.origin === origin ? selected.selector : "",
        });
      } else if (
        message.type === "user-css:draft" ||
        message.type === "user-css:apply"
      ) {
        if (
          message.origin !== origin ||
          typeof message.css !== "string" ||
          message.css.length > 100000
        )
          throw new Error("Unavailable");
        await chrome.storage.session.set({ [draftKey]: message.css });
        if (message.type === "user-css:apply") {
          await chrome.storage.local.set({ [key]: message.css });
          const result = await chrome.tabs.sendMessage(tab.id, {
            type: "user-css:apply-now",
          });
          if (!result?.success) throw new Error("Apply unavailable");
        }
        respond({ success: true });
      } else if (message.type === "user-css:reset") {
        if (message.origin !== origin) throw new Error("Unavailable");
        await chrome.storage.local.remove(key);
        await chrome.storage.session.remove([draftKey, selectionKey]);
        await chrome.tabs
          .sendMessage(tab.id, { type: "user-css:apply-now" })
          .catch(() => {});
        respond({ success: true });
      } else if (message.type === "user-css:pick") {
        if (message.origin !== origin) throw new Error("Unavailable");
        const result = await chrome.tabs.sendMessage(tab.id, {
          type: "user-css:begin-pick",
        });
        if (!result?.success) throw new Error("Picker unavailable");
        respond({ success: true });
      }
    })().catch(() => respond({ error: true }));
    return true;
  });
  chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.session
      .remove(["user-css-selection:" + tabId, "user-css-applied:" + tabId])
      .catch(() => {});
  });
}

function webFilterCssContent() {
  if (
    window.top !== window ||
    !/^https?:$/.test(location.protocol) ||
    (location.origin === "https://education.munetios.com" &&
      /^\/block(?:\.html)?$/.test(location.pathname))
  )
    return;
  let enabled = false,
    strings = {},
    stopPicker = () => {},
    fontPromise;
  function loadFont() {
    if (!fontPromise)
      fontPromise = (async () => {
        const response = await chrome.runtime.sendMessage({
          type: "user-css:font",
        });
        if (!response?.font) throw new Error("Font unavailable");
        const bytes = Uint8Array.from(atob(response.font), (character) =>
          character.charCodeAt(0),
        );
        const face = new FontFace("Munetios Picker Sans", bytes, {
          weight: "100 1000",
          style: "normal",
        });
        await face.load();
        document.fonts.add(face);
      })().catch((error) => {
        fontPromise = null;
        throw error;
      });
    return fontPromise;
  }
  async function refresh() {
    try {
      const state = await chrome.runtime.sendMessage({
        type: "user-css:ready",
      });
      enabled = state?.enabled === true;
      strings = state?.strings || {};
      if (!enabled) stopPicker();
    } catch {
      enabled = false;
      stopPicker();
    }
  }
  refresh();
  chrome.storage.onChanged.addListener((changes, area) => {
    if (
      area === "managed" ||
      (area === "local" &&
        Object.hasOwn(changes, "user-css:" + location.origin))
    )
      refresh();
  });
  function selectorFor(element) {
    const parts = [];
    for (
      let current = element;
      current && current.nodeType === 1;
      current = current.parentElement
    ) {
      if (
        current.id &&
        document.querySelectorAll("#" + CSS.escape(current.id)).length === 1
      ) {
        parts.unshift("#" + CSS.escape(current.id));
        break;
      }
      let part = current.localName;
      const siblings = current.parentElement
        ? [...current.parentElement.children].filter(
            (item) => item.localName === current.localName,
          )
        : [];
      if (siblings.length > 1)
        part += ":nth-of-type(" + (siblings.indexOf(current) + 1) + ")";
      parts.unshift(part);
      const selector = parts.join(" > ");
      if (document.querySelectorAll(selector).length === 1) break;
    }
    return parts.join(" > ");
  }
  async function pick() {
    await refresh();
    if (!enabled) throw new Error("Disabled");
    await loadFont();
    stopPicker();
    const host = document.createElement("div");
    host.style.cssText =
      "all:initial!important;display:block!important;position:fixed!important;inset:0!important;z-index:2147483647!important;pointer-events:none!important;";
    const root = host.attachShadow({ mode: "closed" });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(
      ':host{font-family:"Google Sans Flex",system-ui,sans-serif} .hint{box-sizing:border-box;position:fixed;top:12px;left:50%;transform:translateX(-50%);width:min(980px,calc(100vw - 32px));padding:18px 24px;border:1px solid rgba(168,85,247,.5);border-radius:18px;background:rgba(50,13,82,.5);backdrop-filter:blur(3px);color:white;text-align:center;font:clamp(14px,2vw,17px)/1.6 "Munetios Picker Sans",system-ui,sans-serif;box-shadow:0 8px 24px rgba(15,0,30,.3)} .outline{position:fixed;box-sizing:border-box;border:2px solid #a855f7;border-radius:4px;background:rgba(168,85,247,.15)}',
    );
    root.adoptedStyleSheets = [sheet];
    const hint = document.createElement("div"),
      outline = document.createElement("div");
    hint.className = "hint liquid-glass";
    hint.textContent = strings.pickerInstructions || "";
    outline.className = "outline";
    outline.hidden = true;
    root.append(outline, hint);
    document.documentElement.append(host);
    let selected,
      lastX = 0,
      lastY = 0,
      frame = 0;
    const show = () => {
      frame = 0;
      selected = document.elementFromPoint(lastX, lastY);
      if (!selected || selected === host) {
        outline.hidden = true;
        return;
      }
      const rect = selected.getBoundingClientRect();
      outline.hidden = false;
      Object.assign(outline.style, {
        left: rect.left + "px",
        top: rect.top + "px",
        width: rect.width + "px",
        height: rect.height + "px",
      });
    };
    const move = (event) => {
      lastX = event.clientX;
      lastY = event.clientY;
      if (!frame) frame = requestAnimationFrame(show);
    };
    const prevent = (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
    };
    const choose = (event) => {
      prevent(event);
      const element = document.elementFromPoint(event.clientX, event.clientY);
      if (!element || element === host) return;
      const selector = selectorFor(element);
      stopPicker();
      chrome.runtime
        .sendMessage({ type: "user-css:selected", selector })
        .catch(() => {});
    };
    const keydown = (event) => {
      if (event.key === "Escape") {
        prevent(event);
        stopPicker();
      }
    };
    window.addEventListener("pointermove", move, true);
    window.addEventListener("pointerdown", prevent, true);
    window.addEventListener("click", choose, true);
    window.addEventListener("keydown", keydown, true);
    window.addEventListener("scroll", show, true);
    stopPicker = () => {
      if (frame) cancelAnimationFrame(frame);
      host.remove();
      window.removeEventListener("pointermove", move, true);
      window.removeEventListener("pointerdown", prevent, true);
      window.removeEventListener("click", choose, true);
      window.removeEventListener("keydown", keydown, true);
      window.removeEventListener("scroll", show, true);
      stopPicker = () => {};
    };
  }
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return;
    if (message?.type === "user-css:apply-now") {
      refresh().then(() => respond({ success: enabled }));
      return true;
    }
    if (message?.type !== "user-css:begin-pick") return;
    pick()
      .then(() => respond({ success: true }))
      .catch(() => respond({ success: false }));
    return true;
  });
}

function webFilterCssPopup(fallbackStrings, locale) {
  const byId = (id) => document.getElementById(id);
  const editor = byId("cssEditor"),
    status = byId("cssStatus");
  let state = { strings: fallbackStrings, locale },
    timer,
    pending = false,
    draftWrite = Promise.resolve();
  const send = (type, extra = {}) =>
    chrome.runtime.sendMessage({ type: "user-css:" + type, ...extra });
  function message(key) {
    status.textContent = state?.strings?.[key] || "";
  }
  function busy(value) {
    pending = value;
    editor.disabled = value || !state?.enabled || !state?.usable;
    for (const id of ["applyCss", "resetCss", "pickElement"])
      byId(id).disabled = value || !state?.enabled || !state?.usable;
  }
  function saveDraft() {
    clearTimeout(timer);
    const origin = state.origin,
      css = editor.value;
    draftWrite = draftWrite
      .catch(() => {})
      .then(async () => {
        const result = await send("draft", { origin, css });
        if (!result?.success) throw new Error("Draft failed");
      });
    return draftWrite;
  }
  async function initialize() {
    const response = await send("state");
    if (!response || response.error) throw new Error("Unavailable");
    state = response;
    document.documentElement.lang = state.locale;
    document.title = state.strings.customizeWebsite;
    document.querySelectorAll("[data-i18n]").forEach((element) => {
      element.textContent = state.strings[element.dataset.i18n] || "";
    });
    byId("schoolName").textContent = state.schoolName;
    byId("websiteOrigin").textContent = state.origin || "";
    editor.value = state.css || "";
    if (state.selector) {
      byId("selectedElement").textContent = state.selector;
      byId("selection").hidden = false;
      if (!editor.value.includes(state.selector + " {")) {
        editor.value +=
          (editor.value ? "\n\n" : "") + state.selector + " {\n  \n}";
        await saveDraft();
      }
    }
    editor.disabled = !state.enabled || !state.usable;
    busy(false);
    if (!state.enabled) message("cssDisabled");
    else if (!state.usable) message("cssUnavailable");
  }
  editor.addEventListener("input", () => {
    status.textContent = "";
    clearTimeout(timer);
    timer = setTimeout(
      () => saveDraft().catch(() => message("cssFailed")),
      150,
    );
  });
  byId("applyCss").addEventListener("click", async () => {
    if (pending) return;
    busy(true);
    try {
      await saveDraft();
      const result = await send("apply", {
        origin: state.origin,
        css: editor.value,
      });
      if (!result?.success) throw new Error("Apply failed");
      message("cssSaved");
    } catch {
      message("cssFailed");
    } finally {
      busy(false);
    }
  });
  byId("resetCss").addEventListener("click", async () => {
    if (pending) return;
    busy(true);
    clearTimeout(timer);
    try {
      await draftWrite.catch(() => {});
      const result = await send("reset", { origin: state.origin });
      if (!result?.success) throw new Error("Reset failed");
      editor.value = "";
      byId("selection").hidden = true;
      message("cssCleared");
    } catch {
      message("cssFailed");
    } finally {
      busy(false);
    }
  });
  byId("pickElement").addEventListener("click", async () => {
    if (pending) return;
    busy(true);
    try {
      await saveDraft();
      const result = await send("pick", { origin: state.origin });
      if (!result?.success) throw new Error("Picker failed");
      window.close();
    } catch {
      message("cssFailed");
      busy(false);
    }
  });
  initialize().catch(() => {
    message("cssUnavailable");
    busy(true);
  });
}

function webFilterCssFiles(strings, locale) {
  const html = [
    '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>Munetios WebFilter</title><link rel="stylesheet" href="https://api.munetios.com/beautiful-css/beautiful.css"><link rel="stylesheet" href="customize.css"></head><body>',
    '<header><div class="liquid-glass brand" id="schoolName"></div></header>',
    '<main class="liquid-glass"><h1 data-i18n="customizeWebsite"></h1><p class="origin" id="websiteOrigin"></p>',
    '<label for="cssEditor" data-i18n="cssCode"></label><textarea id="cssEditor" spellcheck="false" autocapitalize="off" autocomplete="off" maxlength="100000" aria-describedby="cssHint" disabled></textarea>',
    '<p class="hint" id="cssHint" data-i18n="cssEditingHint"></p>',
    '<p id="selection" hidden><span data-i18n="pickedElement"></span>: <code id="selectedElement"></code></p>',
    '<div class="actions"><button id="applyCss" data-i18n="applyCss" disabled></button><button id="resetCss" data-i18n="resetCss" disabled></button></div>',
    '<button class="picker" id="pickElement" data-i18n="pickElement" disabled></button><p role="status" aria-live="polite" id="cssStatus"></p></main>',
    '<script src="customize.js"></script></body></html>',
  ].join("");
  const css = [
    '@font-face{font-family:"Google Sans Flex";src:url("fonts/googlesansflex.ttf") format("truetype");font-weight:100 1000;font-style:normal;font-display:swap}',
    ':root{color-scheme:dark;font-family:"Google Sans Flex","Google Sans",system-ui,sans-serif;color:#f8f1ff;background:#160a25}',
    "*{box-sizing:border-box}body{margin:0;width:680px;max-width:100vw;padding:16px;background:radial-gradient(at top right,rgba(126,34,206,.3),transparent 65%)}",
    ".liquid-glass{background:rgba(83,30,128,.3);border:1px solid rgba(190,149,230,.3);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px);border-radius:18px}",
    "header{display:flex;background:transparent;margin-bottom:12px}.brand{padding:10px 14px;font-size:13px;overflow-wrap:anywhere}",
    "main{padding:16px}h1{font-size:19px;margin:0 0 8px}p{font-size:12px;line-height:1.5;overflow-wrap:anywhere}.origin,.hint{color:#d3bce9}label{display:block;margin:14px 0 8px;font-size:13px}",
    "textarea{display:block;width:100%;height:250px;resize:vertical;padding:12px;border:1px solid rgba(190,149,230,.3);border-radius:12px;background:rgba(15,3,29,.4);color:#fff;font:13px/1.6 ui-monospace,Consolas,monospace;tab-size:2}",
    "button{font:inherit;font-size:13px;color:#fff;background:rgba(126,34,206,.4);border:1px solid rgba(190,149,230,.4);border-radius:12px;padding:10px 14px;cursor:pointer}button:disabled,textarea:disabled{opacity:.5;cursor:default}",
    "button:focus-visible,textarea:focus-visible{outline:2px solid #b77aff;outline-offset:2px}.actions{display:flex;gap:8px;margin:14px 0}.picker{width:100%;text-align:center}#cssStatus{min-height:18px;margin-bottom:0}code{font-size:12px}[hidden]{display:none!important}",
    "@media(max-width:340px){body{width:320px;padding:10px}main{padding:12px}.actions{flex-wrap:wrap}}",
  ].join("\n");
  return [
    { name: "customize.html", data: html },
    { name: "customize.css", data: css },
    {
      name: "customize.js",
      data:
        "(" +
        webFilterCssPopup.toString() +
        ")(" +
        JSON.stringify(strings) +
        "," +
        JSON.stringify(locale) +
        ");",
    },
    {
      name: "user-css.js",
      data: "(" + webFilterCssContent.toString() + ")();",
    },
  ];
}
