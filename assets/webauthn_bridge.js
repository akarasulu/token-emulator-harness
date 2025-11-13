(function () {
  const DEFAULT_BASE = "http://localhost:8080";
  const harnessBase = window.__TOKEN_HARNESS_URL || DEFAULT_BASE;
  const state = { pending: null };
  let panel;
  let messageEl;
  let actionBtn;

  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64urlToBuffer(value) {
    const pad = "=".repeat((4 - (value.length % 4)) % 4);
    const base64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  async function callHarness(path, payload) {
    const res = await fetch(`${harnessBase}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Harness error ${res.status}`);
    }
    return res.json();
  }

  function ensurePanel() {
    if (panel) return;
    panel = document.createElement("div");
    panel.id = "token-harness-panel";
    Object.assign(panel.style, {
      position: "fixed",
      top: "1rem",
      right: "1rem",
      background: "#111",
      color: "#fff",
      padding: "1rem",
      borderRadius: "8px",
      boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
      zIndex: 2147483647,
      fontFamily: "sans-serif",
      maxWidth: "320px",
      display: "flex",
      flexDirection: "column",
      gap: "0.5rem",
    });
    messageEl = document.createElement("div");
    actionBtn = document.createElement("button");
    actionBtn.textContent = "Waiting…";
    actionBtn.disabled = true;
    Object.assign(actionBtn.style, {
      background: "#00b894",
      border: "none",
      color: "#fff",
      padding: "0.5rem 1rem",
      borderRadius: "4px",
      cursor: "pointer",
      opacity: "0.7",
    });
    actionBtn.addEventListener("click", async () => {
      if (!state.pending) return;
      actionBtn.disabled = true;
      actionBtn.textContent = "Processing...";
      actionBtn.style.opacity = "0.7";
      try {
        if (state.pending.type === "create") {
          const payload = serializeCreation(state.pending.options);
          const response = await callHarness("/bridge/register", payload);
          state.pending.resolve(formatAttestation(response));
        } else {
          const payload = serializeRequest(state.pending.options);
          const response = await callHarness("/bridge/authenticate", payload);
          state.pending.resolve(formatAssertion(response));
        }
      } catch (err) {
        state.pending.reject(err);
      } finally {
        actionBtn.disabled = false;
        actionBtn.textContent = "Send via Harness";
        panel.style.display = "none";
        state.pending = null;
      }
    });
    panel.appendChild(messageEl);
    panel.appendChild(actionBtn);
    document.body.appendChild(panel);
    setStatus("Harness bridge idle – waiting for WebAuthn request.");
  }

  function setStatus(text, buttonEnabled = false, buttonLabel = "Waiting…") {
    ensurePanel();
    messageEl.textContent = text;
    actionBtn.disabled = !buttonEnabled;
    actionBtn.textContent = buttonLabel;
    actionBtn.style.opacity = buttonEnabled ? "1" : "0.7";
  }

  function promptUser(type) {
    const label = type === "create" ? "registration" : "authentication";
    setStatus(`Harness intercepted WebAuthn ${label} request.`, true, "Send via Harness");
  }

  function serializeCreation(publicKey) {
    return {
      challenge: bufferToBase64url(publicKey.challenge),
      origin: window.location.origin,
      rp: publicKey.rp,
      user: {
        ...publicKey.user,
        id: bufferToBase64url(publicKey.user.id),
      },
      pubKeyCredParams: publicKey.pubKeyCredParams || [],
      timeout: publicKey.timeout,
      attestation: publicKey.attestation || "none",
    };
  }

  function serializeRequest(publicKey) {
    return {
      challenge: bufferToBase64url(publicKey.challenge),
      origin: window.location.origin,
      rpId: publicKey.rpId || window.location.hostname,
      allowCredentials: (publicKey.allowCredentials || []).map((cred) => ({
        id: bufferToBase64url(cred.id),
        type: cred.type || "public-key",
      })),
      userVerification: publicKey.userVerification || "preferred",
      timeout: publicKey.timeout,
    };
  }

  function formatAttestation(payload) {
    return {
      id: payload.id,
      rawId: base64urlToBuffer(payload.rawId),
      type: payload.type,
      response: {
        clientDataJSON: base64urlToBuffer(payload.response.clientDataJSON),
        attestationObject: base64urlToBuffer(payload.response.attestationObject),
      },
      authenticatorAttachment: "harness-virtual",
    };
  }

  function formatAssertion(payload) {
    return {
      id: payload.id,
      rawId: base64urlToBuffer(payload.rawId),
      type: payload.type,
      response: {
        clientDataJSON: base64urlToBuffer(payload.response.clientDataJSON),
        authenticatorData: base64urlToBuffer(payload.response.authenticatorData),
        signature: base64urlToBuffer(payload.response.signature),
        userHandle: payload.response.userHandle
          ? base64urlToBuffer(payload.response.userHandle)
          : null,
      },
      authenticatorAttachment: "harness-virtual",
    };
  }

  if (!navigator.credentials || navigator.credentials.__harnessWrapped) {
    return;
  }

  const nativeCreate = navigator.credentials.create.bind(navigator.credentials);
  const nativeGet = navigator.credentials.get.bind(navigator.credentials);

  navigator.credentials.create = function (options) {
    if (!options || !options.publicKey) {
      return nativeCreate.apply(this, arguments);
    }
    return new Promise((resolve, reject) => {
      if (state.pending) {
        console.warn("Harness busy, falling back to native create.");
        resolve(nativeCreate.apply(navigator.credentials, [options]));
        return;
      }
      state.pending = { type: "create", options: options.publicKey, resolve, reject };
      promptUser("create");
    });
  };

  navigator.credentials.get = function (options) {
    if (!options || !options.publicKey) {
      return nativeGet.apply(this, arguments);
    }
    return new Promise((resolve, reject) => {
      if (state.pending) {
        console.warn("Harness busy, falling back to native get.");
        resolve(nativeGet.apply(navigator.credentials, [options]));
        return;
      }
      state.pending = { type: "get", options: options.publicKey, resolve, reject };
      promptUser("get");
    });
  };

  navigator.credentials.__harnessWrapped = true;
  setStatus("Harness bridge ready – awaiting WebAuthn calls.");
  console.info("Token emulator harness WebAuthn bridge enabled.");
})();
