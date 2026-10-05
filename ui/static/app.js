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

  for (const id of ["root-start", "inter-start"]) {
    const input = document.getElementById(id);
    if (input && !input.value) {
      input.value = defaultStartValue();
    }
  }

  for (const id of ["root-expiry", "inter-expiry"]) {
    const input = document.getElementById(id);
    if (input && !input.value) {
      input.value = defaultExpiryValue();
    }
  }

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

  document.getElementById("chain-save").addEventListener("change", (e) => {
    document.getElementById("chain-out-field").hidden = !e.target.checked;
  });

  document.querySelector('[data-action="gen-chain"]').addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const status = document.getElementById("status-chain");
    const results = document.getElementById("results-chain");
    const leaves = leafCountValue();
    if (!Number.isInteger(leaves) || leaves < 1 || leaves > 100) {
      results.hidden = true;
      setStatus(status, "Leaf count must be a whole number from 1 to 100.", "err");
      return;
    }
    const save = document.getElementById("chain-save").checked;
    const outDir = document.getElementById("chain-out").value;
    if (save) {
      const pathError = invalidSaveDir(outDir);
      if (pathError) {
        results.hidden = true;
        setStatus(status, pathError, "err");
        return;
      }
    }

    setBusy(btn, true);
    setStatus(status, `Generating RSA 4096 keys for the root, intermediate, and ${leafPhrase(leaves)}… this can take a while.`);
    try {
      const data = await postJSON("/api/gen/chain", { leaves });
      const prefix = save ? chainPrefix(outDir) : "";
      renderChain(results, data, prefix);
      results.hidden = false;
      if (save) {
        setStatus(status, "Saving certificates and keys…");
        const written = await saveChainFiles(prefix, data);
        const where = prefix ? prefix.replace(/\/$/, "") : "the current directory";
        setStatus(status, `Generated root, intermediate, and ${leafPhrase(leaves)}. Saved ${written} files to ${where}.`, "ok");
      } else {
        setStatus(status, `Generated root, intermediate, and ${leafPhrase(leaves)}.`, "ok");
      }
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
      const start = startValue("root-start");
      const expiry = expiryValue("root-expiry");
      const data = await postJSON("/api/gen/root", { start, expiry });
      renderBundle(document.querySelector('[data-bundle="root"]'), data, defaults.root);
      results.hidden = false;
      setStatus(status, `Generated root CA. ${expiryStatus(expiry)}`, "ok");
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
      const start = startValue("inter-start");
      const expiry = expiryValue("inter-expiry");
      const data = await postJSON("/api/gen/inter", {
        rootCert: document.getElementById("inter-root-cert").value,
        rootKey: document.getElementById("inter-root-key").value,
        start,
        expiry,
      });
      renderBundle(document.querySelector('[data-bundle="inter"]'), data, defaults.inter);
      results.hidden = false;
      setStatus(status, `Generated intermediate CA. ${expiryStatus(expiry)}`, "ok");
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

  function leafCountValue() {
    const raw = document.getElementById("chain-leaves").value.trim();
    if (!/^\d+$/.test(raw)) {
      return NaN;
    }
    return Number(raw);
  }

  function leafPhrase(n) {
    return n === 1 ? "1 leaf certificate" : `${n} leaf certificates`;
  }

  function invalidSaveDir(dir) {
    const clean = dir.trim();
    if (!clean || clean === ".") {
      return "";
    }
    if (clean.startsWith("/") || clean.startsWith("\\") || /^[A-Za-z]:/.test(clean)) {
      return "absolute paths are not allowed";
    }
    if (clean.split(/[/\\]/).includes("..")) {
      return "invalid path";
    }
    return "";
  }

  function chainPrefix(dir) {
    let clean = dir.trim().replace(/\\/g, "/");
    if (clean === "." || clean === "./") {
      return "";
    }
    clean = clean.replace(/^\.\//, "").replace(/\/+$/, "");
    if (!clean) {
      return "";
    }
    return `${clean}/`;
  }

  function renderChain(container, data, prefix) {
    container.replaceChildren();
    container.appendChild(chainGroup("Root CA", data.root, prefixedPaths(prefix, defaults.root)));
    container.appendChild(chainGroup("Intermediate CA", data.intermediate, prefixedPaths(prefix, defaults.inter)));
    (data.leaves || []).forEach((leaf, index) => {
      const n = index + 1;
      container.appendChild(chainGroup(leaf.commonName || `Leaf ${n}`, leaf, prefixedPaths(prefix, {
        cert: `leaf-${n}.pem`,
        privateKey: `leaf-${n}-key.pem`,
        publicKey: `leaf-${n}-key.pub`,
      })));
    });
  }

  function chainGroup(title, bundle, paths) {
    const group = document.createElement("div");
    group.className = "result-group";
    const heading = document.createElement("h3");
    heading.textContent = title;
    const bundleEl = document.createElement("div");
    bundleEl.className = "bundle";
    group.append(heading, bundleEl);
    renderBundle(bundleEl, bundle, paths);
    return group;
  }

  function prefixedPaths(prefix, paths) {
    return {
      cert: prefix + paths.cert,
      privateKey: prefix + paths.privateKey,
      publicKey: prefix + paths.publicKey,
    };
  }

  async function saveChainFiles(prefix, data) {
    const files = [
      [prefix + defaults.root.cert, data.root.cert],
      [prefix + defaults.root.privateKey, data.root.privateKey],
      [prefix + defaults.root.publicKey, data.root.publicKey],
      [prefix + defaults.inter.cert, data.intermediate.cert],
      [prefix + defaults.inter.privateKey, data.intermediate.privateKey],
      [prefix + defaults.inter.publicKey, data.intermediate.publicKey],
    ];
    (data.leaves || []).forEach((leaf, index) => {
      const n = index + 1;
      files.push([prefix + `leaf-${n}.pem`, leaf.cert]);
      files.push([prefix + `leaf-${n}-key.pem`, leaf.privateKey]);
      files.push([prefix + `leaf-${n}-key.pub`, leaf.publicKey]);
    });
    for (const [path, content] of files) {
      await postJSON("/api/save", { path, content });
    }
    return files.length;
  }

  function defaultStartValue() {
    const date = new Date();
    return formatISODate(date);
  }

  function defaultExpiryValue() {
    const date = new Date();
    date.setFullYear(date.getFullYear() + 10);
    return formatISODate(date);
  }

  function formatISODate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  }

  function startValue(id) {
    return filledDate(id, defaultStartValue);
  }

  function expiryValue(id) {
    return filledDate(id, defaultExpiryValue);
  }

  function filledDate(id, fallback) {
    const input = document.getElementById(id);
    if (!input.value) {
      input.value = fallback();
    }
    return input.value;
  }

  function expiryStatus(value) {
    if (value < formatISODate(new Date())) {
      return `Expires ${value} (already expired).`;
    }
    return `Expires ${value}.`;
  }

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
