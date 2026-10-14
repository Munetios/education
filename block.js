(() => {
  if (document.documentElement.dataset.munetiosWebfilterBridge) return;
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get("url") || "";
  const blockedCategory = params.get("category") || "";
  const bypassButton = document.getElementById("bypass-button");
  const contactButton = document.getElementById("contact-button");
  const bypassPanel = document.querySelector(".bypass-password");
  const passwordInput = document.getElementById("bypass-password-input");
  const submitButton = document.getElementById("submit-bypass-button");
  const errorBox = document.querySelector(".bypass-errors");
  const errorMessages = [...document.querySelectorAll(".error-message")];
  let config = null;

  document.getElementById("website-url").textContent = blockedUrl;
  document.getElementById("website-category").textContent = blockedCategory;

  function setText(id, value) {
    if (!value) return;
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function applyConfig(nextConfig) {
    config = nextConfig;
    const strings = config.strings || {};
    document.documentElement.lang = config.locale || "en-US";
    document.title = `${strings.blockedTitle || "This site has been blocked by your Administrator"} - Munetios WebFilter`;
    setText("school-name", config.schoolName || "Munetios WebFilter");
    setText("blocked-title", strings.blockedTitle);
    setText("blocked-description", strings.blockedDescription);
    setText("url-label", strings.url);
    setText("category-label", strings.category);
    setText("bypass-label", strings.bypass);
    setText("contact-label", strings.contact);
    setText("bypass-title", strings.enterPassword);
    setText("submit-label", strings.submit);
    setText("error-incorrect", strings.incorrect);
    setText("error-empty", strings.empty);
    setText("error-short", strings.tooShort);
    setText("error-invalid", strings.invalid);
    setText("error-extension", strings.notExtension);
    setText("error-failed", strings.failed);
    setText("bypass-note", strings.temporary);
    if (strings.passwordPlaceholder) {
      passwordInput.placeholder = strings.passwordPlaceholder;
    }
    if (!blockedCategory) {
      document.getElementById("website-category").textContent =
        strings.categoryFallback || "Custom URLs";
    }
  }

  function setError(id) {
    errorBox.classList.add("visible");
    errorMessages.forEach((message) => {
      message.style.display = message.id === id ? "block" : "none";
    });
  }

  function clearErrors() {
    errorBox.classList.remove("visible");
    errorMessages.forEach((message) => {
      message.style.display = "none";
    });
  }

  function toggleBypassPanel() {
    const isVisible = bypassPanel.classList.contains("visible");
    bypassPanel.classList.toggle("visible", !isVisible);
    bypassPanel.classList.toggle("hidden", isVisible);
    if (!isVisible) {
      passwordInput.focus();
    } else {
      passwordInput.value = "";
      clearErrors();
    }
  }

  async function tryBypass(password) {
    if (!(window.chrome && chrome.runtime && chrome.runtime.sendMessage)) {
      return { success: false, reason: "not-extension" };
    }
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "verify-bypass", value: password, url: blockedUrl },
        (response) => {
          if (chrome.runtime.lastError) {
            resolve({ success: false, reason: "failed" });
            return;
          }
          resolve(response || { success: false, reason: "incorrect" });
        },
      );
    });
  }

  bypassButton.addEventListener("click", toggleBypassPanel);
  contactButton.addEventListener("click", () => {
    const adminEmail = config?.contactEmail || "administrator@example.com";
    const subject = encodeURIComponent("Access request for blocked website");
    const body = encodeURIComponent(
      `Hello,\n\nI would like to request access to ${blockedUrl}.\nPlease review this block.`,
    );
    window.location.href = `mailto:${adminEmail}?subject=${subject}&body=${body}`;
  });

  submitButton.addEventListener("click", async () => {
    clearErrors();
    const value = passwordInput.value.trim();
    if (!value) {
      setError("error-empty");
      return;
    }
    if (value.length < 4) {
      setError("error-short");
      return;
    }
    const validChars = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/\\~`"']+$/;
    if (!validChars.test(value)) {
      setError("error-invalid");
      return;
    }
    try {
      const result = await tryBypass(value);
      if (result.success && blockedUrl) {
        window.location.href = result.url || blockedUrl;
        return;
      }
      if (result.reason === "not-extension") {
        setError("error-extension");
        return;
      }
      if (result.reason === "failed") {
        setError("error-failed");
        return;
      }
      setError("error-incorrect");
    } catch {
      setError("error-failed");
    }
  });

  passwordInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submitButton.click();
  });

  fetch("config.json")
    .then((response) => {
      if (!response.ok) throw new Error("Configuration unavailable");
      return response.json();
    })
    .then(applyConfig)
    .catch(() => {
      if (!blockedCategory) {
        document.getElementById("website-category").textContent = "Custom URLs";
      }
    });
})();
