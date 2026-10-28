(() => {
  const defaults = {
    root: {
      cert: "rootcert.pem",
      privateKey: "root.key",
      publicKey: "root.pub",
    },
    inter: {
      cert: "intermediate.pem",
      privateKey: "intermediate.key",
      publicKey: "intermediate.pub",
    },
  };

  const fieldMeta = {
    cert: { title: "Certificate", kind: "cert" },
    privateKey: { title: "Private key", kind: "key" },
    publicKey: { title: "Public key", kind: "pub" },
  };

  for (const id of [
    "generate-root-start",
    "generate-intermediate-start",
    "generate-leaf-start",
  ]) {
    const input = document.getElementById(id);
    if (input && !input.value) {
      input.value = defaultStartValue();
    }
  }

  for (const [id, years] of [
    ["generate-root-expiry", 10],
    ["generate-intermediate-expiry", 5],
    ["generate-leaf-expiry", 1],
  ]) {
    const input = document.getElementById(id);
    if (input && !input.value) {
      input.value = defaultExpiryInYears(years);
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

  document.getElementById("generate-save").addEventListener("change", (e) => {
    document.getElementById("generate-out-field").hidden = !e.target.checked;
  });

  document.querySelector('[data-action="gen-generate"]').addEventListener("click", async (e) => {
    await generateChainPanel({
      btn: e.currentTarget,
      statusId: "status-generate",
      resultsId: "results-generate",
      leavesId: "generate-leaves",
      saveId: "generate-save",
      outId: "generate-out",
      namePrefixId: "generate-prefix",
      names: {
        root: {
          cert: "rootcert.pem",
          privateKey: "root.key",
          publicKey: "root.pub",
        },
        inter: {
          cert: "intermediate.pem",
          privateKey: "intermediate.key",
          publicKey: "intermediate.pub",
        },
        leaf: (n) => ({
          cert: `leaf-${n}.pem`,
          privateKey: `leaf-${n}.key`,
          publicKey: `leaf-${n}.pub`,
        }),
      },
      endpoint: "/api/gen/test",
      body: (leaves) => ({
        leaves,
        organization: document.getElementById("generate-organization").value,
        rootCN: document.getElementById("generate-root-cn").value,
        intermediateCN: document.getElementById("generate-intermediate-cn").value,
        rootStart: startValue("generate-root-start"),
        rootExpiry: expiryValue("generate-root-expiry"),
        intermediateStart: startValue("generate-intermediate-start"),
        intermediateExpiry: filledDate("generate-intermediate-expiry", () => defaultExpiryInYears(5)),
        leafStart: startValue("generate-leaf-start"),
        leafExpiry: filledDate("generate-leaf-expiry", () => defaultExpiryInYears(1)),
      }),
    });
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

  document.querySelector('[data-action="view"]').addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const status = document.getElementById("status-view");
    const results = document.getElementById("results-view");
    setBusy(btn, true);
    setStatus(status, "Decoding certificate…");
    try {
      const data = await postJSON("/api/view", {
        cert: document.getElementById("view-cert").value,
      });
      document.getElementById("view-cert-text").value = data.certificate || "";
      results.hidden = false;
      setStatus(status, "Decoded certificate.", "ok");
    } catch (err) {
      results.hidden = true;
      setStatus(status, err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  async function generateChainPanel({ btn, statusId, resultsId, leavesId, saveId, outId, namePrefixId, names, endpoint, body }) {
    const status = document.getElementById(statusId);
    const results = document.getElementById(resultsId);
    const leaves = leafCountValue(leavesId);
    if (!Number.isInteger(leaves) || leaves < 1 || leaves > 100) {
      results.hidden = true;
      setStatus(status, "Leaf count must be a whole number from 1 to 100.", "err");
      return;
    }
    const save = document.getElementById(saveId).checked;
    const outDir = document.getElementById(outId).value;
    const namePrefix = namePrefixId ? document.getElementById(namePrefixId).value : "";
    if (save) {
      const pathError = invalidSaveDir(outDir);
      if (pathError) {
        results.hidden = true;
        setStatus(status, pathError, "err");
        return;
      }
      const nameError = invalidNamePrefix(namePrefix);
      if (nameError) {
        results.hidden = true;
        setStatus(status, nameError, "err");
        return;
      }
    }

    setBusy(btn, true);
    setStatus(status, `Generating RSA 4096 keys for the root, intermediate, and ${leafPhrase(leaves)}… this can take a while.`);
    try {
      const data = await postJSON(endpoint, body(leaves));
      const dirPrefix = save ? chainPrefix(outDir) : "";
      const filePrefix = save ? namePrefix : "";
      const prefix = dirPrefix + filePrefix;
      renderChain(results, data, prefix, names);
      results.hidden = false;
      if (save) {
        setStatus(status, "Saving certificates and keys…");
        const written = await saveChainFiles(prefix, data, names);
        const where = dirPrefix ? dirPrefix.replace(/\/$/, "") : "the current directory";
        setStatus(status, `Generated root, intermediate, and ${leafPhrase(leaves)}. Saved ${written} files to ${where}.`, "ok");
      } else {
        setStatus(status, `Generated root, intermediate, and ${leafPhrase(leaves)}.`, "ok");
      }
    } catch (err) {
      setStatus(status, err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  }

  function leafCountValue(id) {
    const raw = document.getElementById(id).value.trim();
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

  function invalidNamePrefix(prefix) {
    if (!prefix) {
      return "";
    }
    if (prefix.includes("/") || prefix.includes("\\") || prefix.includes("..")) {
      return "prefix must not contain path separators";
    }
    return "";
  }

  function renderChain(container, data, prefix, names) {
    const rootPaths = names?.root || defaults.root;
    const interPaths = names?.inter || defaults.inter;
    container.replaceChildren();
    container.appendChild(chainGroup("Root CA", data.root, prefixedPaths(prefix, rootPaths)));
    container.appendChild(chainGroup("Intermediate CA", data.intermediate, prefixedPaths(prefix, interPaths)));
    (data.leaves || []).forEach((leaf, index) => {
      const n = index + 1;
      const leafPaths = names?.leaf?.(n) || {
        cert: `leaf-${n}.pem`,
        privateKey: `leaf-${n}.key`,
        publicKey: `leaf-${n}.pub`,
      };
      container.appendChild(chainGroup(leaf.commonName || `Leaf ${n}`, leaf, prefixedPaths(prefix, leafPaths)));
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

  async function saveChainFiles(prefix, data, names) {
    const rootPaths = names?.root || defaults.root;
    const interPaths = names?.inter || defaults.inter;
    const files = [
      [prefix + rootPaths.cert, data.root.cert],
      [prefix + rootPaths.privateKey, data.root.privateKey],
      [prefix + rootPaths.publicKey, data.root.publicKey],
      [prefix + interPaths.cert, data.intermediate.cert],
      [prefix + interPaths.privateKey, data.intermediate.privateKey],
      [prefix + interPaths.publicKey, data.intermediate.publicKey],
    ];
    (data.leaves || []).forEach((leaf, index) => {
      const n = index + 1;
      const leafPaths = names?.leaf?.(n) || {
        cert: `leaf-${n}.pem`,
        privateKey: `leaf-${n}.key`,
        publicKey: `leaf-${n}.pub`,
      };
      files.push([prefix + leafPaths.cert, leaf.cert]);
      files.push([prefix + leafPaths.privateKey, leaf.privateKey]);
      files.push([prefix + leafPaths.publicKey, leaf.publicKey]);
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
    return defaultExpiryInYears(10);
  }

  function defaultExpiryInYears(years) {
    const date = new Date();
    date.setFullYear(date.getFullYear() + years);
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
