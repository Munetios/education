function webFilterHostingUrls(value) {
  try {
    const base = new URL(value.trim());
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('Invalid hosting URL');
    if (base.hostname === 'example' || base.hostname.endsWith('.example')) throw new Error('Invalid hosting URL');
    if (!base.pathname.endsWith('/')) base.pathname += '/';
    return {base: base.href, updateUrl: new URL('update.xml', base).href, crxUrl: new URL('webfilter.crx', base).href};
  } catch {throw new Error('hostingInvalid');}
}

function webFilterVersion(value) {
  if (!/^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,3}$/.test(value) ||
      value.split('.').some(part => Number(part) > 65535) || value.split('.').every(part => Number(part) === 0)) throw new Error('versionInvalid');
  return value;
}

let webFilterFontPromise;
function webFilterFontBytes() {
  if (!webFilterFontPromise) webFilterFontPromise = fetch('assets/googlesansflex.ttf').then(async response => {
    if (!response.ok) throw new Error('fontUnavailable');
    const bytes = new Uint8Array(await response.arrayBuffer());
    const valid = bytes.length > 12 && ((bytes[0] === 0 && bytes[1] === 1 && bytes[2] === 0 && bytes[3] === 0) ||
      String.fromCharCode(...bytes.slice(0, 4)) === 'OTTO');
    if (!valid) throw new Error('fontUnavailable');
    return bytes;
  }).catch(error => {webFilterFontPromise = null; throw error;});
  return webFilterFontPromise;
}

async function webFilterSigningKey(pem) {
  const algorithm = {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'};
  if (!pem) return crypto.subtle.generateKey({...algorithm, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1])}, true, ['sign', 'verify']);
  try {
    if (!/-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----/.test(pem)) throw new Error('Invalid key');
    const bytes = Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')), character => character.charCodeAt(0));
    const privateKey = await crypto.subtle.importKey('pkcs8', bytes, algorithm, true, ['sign']);
    if (privateKey.algorithm.modulusLength < 2048) throw new Error('Weak key');
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    const publicKey = await crypto.subtle.importKey('jwk', {kty: 'RSA', n: jwk.n, e: jwk.e, ext: true}, algorithm, true, ['verify']);
    return {privateKey, publicKey};
  } catch {throw new Error('signingKeyInvalid');}
}

function webFilterBytes(...parts) {
  const bytes = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {bytes.set(part, offset); offset += part.length;}
  return bytes;
}

function webFilterUint32(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

function webFilterProto(number, bytes) {
  const variable = value => {
    const result = [];
    do {const next = value & 127; value = Math.floor(value / 128); result.push(next | (value ? 128 : 0));} while (value);
    return new Uint8Array(result);
  };
  return webFilterBytes(variable(number * 8 + 2), variable(bytes.length), bytes);
}

async function webFilterSignCrx(zip, keys) {
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
  const crxId = hash.slice(0, 16);
  const id = Array.from(crxId, byte => String.fromCharCode(97 + (byte >> 4), 97 + (byte & 15))).join('');
  const signedHeader = webFilterProto(1, crxId);
  const input = webFilterBytes(new TextEncoder().encode('CRX3 SignedData\0'), webFilterUint32(signedHeader.length), signedHeader, zip);
  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keys.privateKey, input));
  const proof = webFilterBytes(webFilterProto(1, publicKey), webFilterProto(2, signature));
  const header = webFilterBytes(webFilterProto(2, proof), webFilterProto(10000, signedHeader));
  const crx = webFilterBytes(new TextEncoder().encode('Cr24'), webFilterUint32(3), webFilterUint32(header.length), header, zip);
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  let binary = '';
  for (let index = 0; index < privateBytes.length; index++) binary += String.fromCharCode(privateBytes[index]);
  const pem = '-----BEGIN PRIVATE KEY-----\n' + btoa(binary).match(/.{1,64}/g).join('\n') + '\n-----END PRIVATE KEY-----\n';
  return {crx, id, pem};
}

function webFilterUpdateXml(id, crxUrl, version) {
  if (!/^[a-p]{32}$/.test(id)) throw new Error('Invalid extension ID');
  webFilterVersion(version);
  const escape = text => text.replace(/[&<>"']/g, character => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;'}[character]));
  return '<?xml version="1.0" encoding="UTF-8"?>\n<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0"><app appid="' + id + '"><updatecheck codebase="' + escape(crxUrl) + '" version="' + version + '" /></app></gupdate>\n';
}

async function webFilterDeployment(files, manifest, config, hosting, keyText, createZip) {
  const keys = await webFilterSigningKey(keyText);
  manifest.update_url = hosting.updateUrl;
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey));
  let publicText = '';
  for (const byte of publicBytes) publicText += String.fromCharCode(byte);
  manifest.key = btoa(publicText);
  files.find(file => file.name === 'manifest.json').data = JSON.stringify(manifest, null, 2);
  const signed = await webFilterSignCrx(createZip(files), keys);
  const pattern = signed.id + ';' + hosting.updateUrl;
  const managed = {SchoolName: config.schoolName, ContactEmail: config.contactEmail,
    EnforceSafeMode: config.enforceSafeMode, AllowUserCss: config.allowUserCss,
    BlockList: config.blockList, BlockedUrlTerms: config.blockedUrlTerms, AllowList: config.allowList, BypassPassword: config.password};
  const policy = {ExtensionInstallForcelist: [pattern], '3rdparty': {extensions: {[signed.id]: {policy: managed}}}};
  const admin = {extensionId: signed.id, updateUrl: hosting.updateUrl, crxUrl: hosting.crxUrl,
    installationPolicy: 'force_installed', version: manifest.version};
  const bundle = [
    {name: 'webfilter.crx', data: signed.crx},
    {name: 'update.xml', data: webFilterUpdateXml(signed.id, hosting.crxUrl, manifest.version)},
    {name: 'google-admin-deployment.json', data: JSON.stringify(admin, null, 2)},
    {name: 'chrome-policy.json', data: JSON.stringify(policy, null, 2)},
    {name: 'managed-policy.json', data: files.find(file => file.name === 'managed-policy.json').data},
    {name: 'DEPLOYMENT.md', data: files.find(file => file.name === 'DEPLOYMENT.md').data + '\n\nGoogle Admin extension ID: ' + signed.id + '\n\nCustom update URL: ' + hosting.updateUrl + '\n\nUpload webfilter.crx and update.xml to the hosting folder. These URLs become usable only after uploading. Keep the separately downloaded signing key private and reuse it for updates. Increase the version for each update. Never include the private key in a hosting upload.\n'},
  ];
  return {id: signed.id, pattern, updateUrl: hosting.updateUrl, crxUrl: hosting.crxUrl, pem: signed.pem, bundle: createZip(bundle)};
}
