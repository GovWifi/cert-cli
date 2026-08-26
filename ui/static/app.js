(() => {
  const defaults = {
    root: {
      cert: "rootcert.pem",
      privateKey: "root-key.pem",
      publicKey: "root-key.pub",
    },
    inter: {
      cert: "intermediate.pem",
      privateKey: "intermediate-key.pem",
      publicKey: "intermediate-key.pub",
    },
  };

  const fieldMeta = {
    cert: { title: "Certificate", kind: "cert" },
    privateKey: { title: "Private key", kind: "key" },
    publicKey: { title: "Public key", kind: "pub" },
  };

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const name = tab.dataset.tab;
      document.querySelectorAll(".tab").forEach((t) => {
        const active = t === tab;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", active ? "true" : "false");
      });
      document.querySelectorAll(".panel").forEach((panel) => {
        const active = panel.id === `panel-${name}`;
        panel.hidden = !active;
        panel.classList.toggle("active", active);
      });
    });
  });

  document.querySelectorAll("input[type=file][data-fill]").forEach((input) => {
    input.addEventListener("change", async () => {
      const file = input.files && input.files[0];
      if (!file) return;
      const target = document.getElementById(input.dataset.fill);
      if (!target) return;
      target.value = await file.text();
      const label = input.closest(".file-btn")?.querySelector("span");
      if (label) {
        label.textContent = file.name;
      }
      input.value = "";
    });
  });

  document.querySelector('[data-action="gen-all"]').addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const status = document.getElementById("status-all");
    const results = document.getElementById("results-all");
    setBusy(btn, true);
    setStatus(status, "Generating RSA 4096 keys… this can take a few seconds.");
    try {
      const data = await postJSON("/api/gen/all");
      renderBundle(document.querySelector('[data-bundle="all-root"]'), data.root, defaults.root);
      renderBundle(document.querySelector('[data-bundle="all-inter"]'), data.intermediate, defaults.inter);
      results.hidden = false;
      setStatus(status, "Generated root and intermediate CA.", "ok");
    } catch (err) {
      setStatus(status, err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  document.querySelector('[data-action="gen-root"]').addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const status = document.getElementById("status-root");
    const results = document.getElementById("results-root");
    setBusy(btn, true);
    setStatus(status, "Generating RSA 4096 keys… this can take a few seconds.");
    try {
      const data = await postJSON("/api/gen/root");
      renderBundle(document.querySelector('[data-bundle="root"]'), data, defaults.root);
      results.hidden = false;
      setStatus(status, "Generated root CA.", "ok");
    } catch (err) {
      setStatus(status, err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  document.querySelector('[data-action="gen-inter"]').addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const status = document.getElementById("status-inter");
    const results = document.getElementById("results-inter");
    setBusy(btn, true);
    setStatus(status, "Generating RSA 4096 keys… this can take a few seconds.");
    try {
      const data = await postJSON("/api/gen/inter", {
        rootCert: document.getElementById("inter-root-cert").value,
        rootKey: document.getElementById("inter-root-key").value,
      });
      renderBundle(document.querySelector('[data-bundle="inter"]'), data, defaults.inter);
      results.hidden = false;
      setStatus(status, "Generated intermediate CA.", "ok");
    } catch (err) {
      setStatus(status, err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  document.querySelector('[data-action="validate"]').addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const status = document.getElementById("status-validate");
    const results = document.getElementById("results-validate");
    setBusy(btn, true);
    setStatus(status, "Checking signature…");
    try {
      const data = await postJSON("/api/validate", {
        cert: document.getElementById("validate-cert").value,
        root: document.getElementById("validate-root").value,
      });
      document.getElementById("validate-cert-text").value = data.certificate || "";
      document.getElementById("validate-root-text").value = data.issuer || "";
      results.hidden = false;
      setStatus(status, data.message, data.ok ? "ok" : "err");
    } catch (err) {
      setStatus(status, err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  function renderBundle(container, bundle, paths) {
    container.replaceChildren();
    for (const key of ["cert", "privateKey", "publicKey"]) {
      container.appendChild(createPemField(fieldMeta[key], bundle[key], paths[key]));
    }
  }

  function createPemField(meta, content, defaultPath) {
    const node = document.getElementById("pem-field-template").content.cloneNode(true);
    const root = node.querySelector(".pem-field");
    root.dataset.kind = meta.kind;
    root.querySelector(".pem-title").textContent = meta.title;
    const badge = root.querySelector(".pem-badge");
    if (meta.kind === "key") {
      badge.style.background = "var(--amber)";
      root.style.borderLeftColor = "var(--amber)";
    } else if (meta.kind === "pub") {
      badge.style.background = "var(--line-strong)";
      root.style.borderLeftColor = "var(--line-strong)";
    }
    const textarea = root.querySelector(".pem-content");
    textarea.value = content || "";
    const pathInput = root.querySelector(".save-path");
    pathInput.value = defaultPath;
    const saveStatus = root.querySelector(".save-status");

    root.querySelector(".copy-btn").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(textarea.value);
        saveStatus.textContent = "copied";
        saveStatus.className = "save-status ok";
      } catch (err) {
        saveStatus.textContent = err.message;
        saveStatus.className = "save-status err";
      }
    });

    root.querySelector(".save-btn").addEventListener("click", async () => {
      saveStatus.textContent = "saving…";
      saveStatus.className = "save-status";
      try {
        const data = await postJSON("/api/save", {
          path: pathInput.value,
          content: textarea.value,
        });
        saveStatus.textContent = data.message || "wrote file";
        saveStatus.className = "save-status ok";
      } catch (err) {
        saveStatus.textContent = err.message;
        saveStatus.className = "save-status err";
      }
    });

    return root;
  }

  async function postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.message || `request failed (${res.status})`);
    }
    return data;
  }

  function setStatus(el, text, kind) {
    el.textContent = text || "";
    el.className = "status" + (kind ? ` ${kind}` : "");
  }

  function setBusy(btn, busy) {
    btn.disabled = busy;
  }
})();
