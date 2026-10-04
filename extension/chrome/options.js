const disconnectedStatus = "Native host disconnected. Origin permission is retained; review the broker and native-host enrollment.";
let nativeDisconnects = 0;
chrome.runtime.onMessage.addListener((message, sender) => {
  if (sender?.id === chrome.runtime.id && sender.url === chrome.runtime.getURL("worker.js") &&
      message?.type === "nativeConnectionStatus" && message.connected === false) {
    nativeDisconnects++;
    document.getElementById("status").textContent = disconnectedStatus;
  }
});
document.getElementById("enroll").addEventListener("click", async () => {
  const status = document.getElementById("status");
  try {
    const profileChannel = document.getElementById("channel").value.trim();
    const browserInstance = document.getElementById("instance").value.trim();
    const origins = [...new Set(document.getElementById("origins").value.split(/\s+/).filter(Boolean))];
    if (!profileChannel || !browserInstance || origins.length === 0 || origins.length > 20) throw Error("Channel, browser instance and 1–20 origins required");
    for (const origin of origins) {
      const url = new URL(origin);
      if (url.origin !== origin || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname)))) throw Error("Use exact HTTPS origins or loopback HTTP origins");
    }
    if (!await chrome.permissions.request({origins: origins.map(o => o + "/*")})) throw Error("Origin permission denied");
    await chrome.storage.local.set({enrollment: {profileChannel, browserInstance, origins}});
    let connection;
    const disconnectVersion = nativeDisconnects;
    try { connection = await chrome.runtime.sendMessage({type: "connect"}); }
    catch { status.textContent = disconnectedStatus; return; }
    if (connection?.connected !== true || nativeDisconnects !== disconnectVersion) { status.textContent = disconnectedStatus; return; }
    status.textContent = "Origins granted. Native host connection opened; broker authorization is still required.";
  } catch (error) {
    const publicErrors = ["Channel, browser instance and 1–20 origins required", "Use exact HTTPS origins or loopback HTTP origins", "Origin permission denied"];
    status.textContent = publicErrors.includes(error?.message) ? error.message : "Enrollment unavailable. Review origins and extension permissions.";
  }
});
