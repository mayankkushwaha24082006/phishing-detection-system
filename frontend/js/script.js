/* script.js - shared code for all pages.
   Each page sets <body data-page="..."> and only that page's code runs. */

   const $ = (s) => document.querySelector(s);
   // Escape text before putting it in HTML (submitted URLs are untrusted input)
   const esc = (s) => String(s).replace(/[&<>"']/g,
     (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
   const when = (iso) => new Date(iso).toLocaleString();   // UTC -> your local time
   
   // Calls the Flask API and returns JSON, or throws an Error with a friendly message
   async function api(path, options) {
     let res;
     try { res = await fetch("/api" + path, options); }
     catch { throw new Error("Cannot reach the server. Is `python backend/app.py` running?"); }
     let data = {};
     try { data = await res.json(); } catch { /* ignore */ }
     if (!res.ok) throw new Error(data.error || "Request failed.");
     return data;
   }
   
   // ---------- shared navigation and footer ----------
   const page = document.body.dataset.page;
   const links = [["index.html", "Home", "home"], ["dashboard.html", "Dashboard", "dashboard"],
                  ["history.html", "History", "history"], ["about.html", "About", "about"]];
   $("#nav").innerHTML = `<nav><div class="wrap"><a class="brand" href="index.html">🛡️ Phish<span>Guard</span> AI</a><div>` +
     links.map(([h, t, k]) => `<a class="link ${k === page ? "on" : ""}" href="${h}">${t}</a>`).join("") +
     `</div></div></nav>`;
   $("#footer").innerHTML = `<footer>AI-Powered Phishing Website Detection System · Decision-support tool, not a guarantee of safety.</footer>`;
   
   // ---------- result card (used by Home and History) ----------
   function renderResult(r, target) {
    // Plain-language text for each risk level
    const text = {
      success: {
        icon: "✅", title: "No major warning signs found",
        say: "This link looks fairly normal. That does not prove it is safe, because no tool can promise that.",
        todo: ["Check that the website name is exactly what you expected.",
               "Do not enter passwords or card details if anything feels wrong.",
               "If unsure, type the official address yourself instead of clicking links."],
      },
      warning: {
        icon: "⚠️", title: "Be careful with this link",
        say: "Some things about this link look unusual. It may be harmless, but it is worth checking first.",
        todo: ["Do not enter passwords, OTPs or card details yet.",
               "Check the website name carefully for spelling tricks.",
               "Open the official website by typing its address yourself, then compare."],
      },
      danger: {
        icon: "⛔", title: "Do not trust this link",
        say: "This link has several signs that are common in phishing (fake) websites.",
        todo: ["Do not open this link or enter any information.",
               "If it came in a message or email, do not reply to it. Delete it or report it as spam.",
               "If you already entered a password, change it now and contact your bank or service."],
      },
    }[r.level];
  
    const sev = { high: "High concern", medium: "Medium concern", low: "Minor" };
  
    // "What we found" list
    let findings;
    if (r.indicators.length) {
      findings = r.indicators.map((i) =>
        `<div class="ind ${esc(i.severity)}"><span class="sev">${sev[i.severity] || "Note"}</span>${esc(i.text)}</div>`).join("");
    } else if (r.level === "success") {
      findings = `<p class="muted">We did not find common phishing tricks such as an @ symbol, an IP address instead of a name, a hidden redirect, or a link shortener.</p>`;
    } else {
      findings = `<div class="ind medium"><span class="sev">Medium concern</span>The website name looks unusual compared with the sites our system learned from. This is based only on the name, so it may be a false alarm.</div>`;
    }
  
    const f = r.features;
    target.innerHTML = `
    <div class="card lvl-${esc(r.level)}">
      <div class="verdict">
        <div class="vicon">${text.icon}</div>
        <div>
          <h3 class="vtitle">${text.title}</h3>
          <p>${text.say}</p>
        </div>
      </div>
  
      <div class="urlbox">${esc(r.url)}</div>
  
      <div class="meter-wrap">
        <div class="meter">
          <span class="zone z1"></span><span class="zone z2"></span><span class="zone z3"></span>
          <span class="marker" style="left:${Math.min(98, Math.max(2, r.risk_score))}%"></span>
        </div>
        <div class="meter-labels"><span>Low risk</span><span>Suspicious</span><span>Phishing</span></div>
        <p class="muted">Risk score: <b>${r.risk_score} out of 100</b>. The higher the number, the riskier the link.</p>
      </div>
  
      <h3>What should I do?</h3>
      <ul class="todo">${text.todo.map((t) => `<li>${t}</li>`).join("")}</ul>
  
      <h3>What we found</h3>
      ${findings}
  
      <details>
        <summary>Technical details (for students and examiners)</summary>
        <p class="muted">Model probability (uncalibrated, domain name only): <b>${(r.model_probability * 100).toFixed(1)}%</b>
        · Rule points: <b>${r.rule_points}</b> · Final risk score: <b>${r.risk_score}</b> (${esc(r.model_name)})</p>
        <div class="tablewrap"><table>
          <tr><th>Length</th><th>Dots</th><th>Hyphens</th><th>Subdomains</th><th>Special chars</th><th>Entropy</th><th>HTTPS</th></tr>
          <tr><td>${f.url_length}</td><td>${f.num_dots}</td><td>${f.num_hyphens}</td><td>${f.num_subdomains}</td>
          <td>${f.num_special_chars}</td><td>${f.url_entropy}</td><td>${f.uses_https ? "Yes" : "No"}</td></tr>
        </table></div>
        <p class="note">${esc(r.disclaimer)}</p>
      </details>
    </div>`;
  }
   
   const badge = (label) => {
     const lvl = { "Low Risk": "success", Suspicious: "warning", Phishing: "danger" }[label] || "success";
     return `<span class="badge lvl-${lvl}">${esc(label)}</span>`;
   };
   
   // ---------- HOME ----------
if (page === "home") {
  const input = $("#url"), btn = $("#scanBtn"), err = $("#error"), out = $("#result");
  async function scan() {
    err.textContent = ""; out.innerHTML = "";
    if (!input.value.trim()) { err.textContent = "Please enter a URL."; return; }
    btn.disabled = true; btn.textContent = "Scanning...";
    try {
      const r = await api("/scan", { method: "POST", headers: { "Content-Type": "application/json" },
                                     body: JSON.stringify({ url: input.value }) });
      renderResult(r, out);
    } catch (e) { err.textContent = e.message; }
    btn.disabled = false; btn.textContent = "Scan Now";
  }
  btn.addEventListener("click", scan);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") scan(); });
  // Example buttons fill the box and scan
  document.querySelectorAll(".chip").forEach((b) =>
    b.addEventListener("click", () => { input.value = b.dataset.url; scan(); }));
}
   
   // ---------- DASHBOARD ----------
   if (page === "dashboard") {
     (async () => {
       try {
         const d = await api("/dashboard");
         $("#total").textContent = d.total_scans; $("#phish").textContent = d.phishing;
         $("#susp").textContent = d.suspicious; $("#low").textContent = d.low_risk;
         $("#avg").textContent = d.average_risk_score ?? "-";
         if (d.total_scans === 0) $("#empty").style.display = "block";
         Chart.defaults.color = "#94A3B8";
         new Chart($("#pie"), { type: "doughnut", data: { labels: ["Phishing", "Suspicious", "Low Risk"],
           datasets: [{ data: [d.phishing, d.suspicious, d.low_risk],
                        backgroundColor: ["#EF4444", "#F59E0B", "#10B981"], borderColor: "#111C30" }] } });
         new Chart($("#bar"), { type: "bar", data: { labels: d.per_day.map((x) => x.date.slice(5)),
           datasets: [
             { label: "Phishing", data: d.per_day.map((x) => x.phishing), backgroundColor: "#EF4444" },
             { label: "Suspicious", data: d.per_day.map((x) => x.suspicious), backgroundColor: "#F59E0B" },
             { label: "Low Risk", data: d.per_day.map((x) => x.low_risk), backgroundColor: "#10B981" }] },
           options: { scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } } });
         $("#recent").innerHTML = d.recent.map((s) =>
           `<tr><td class="u">${esc(s.url)}</td><td>${badge(s.label)}</td><td>${s.risk_score}</td><td>${when(s.created_at)}</td></tr>`).join("");
       } catch (e) { $("#error").textContent = e.message; }
     })();
   }
   
   // ---------- HISTORY ----------
   if (page === "history") {
     async function load() {
       try {
         const d = await api("/history");
         $("#count").textContent = `${d.count} scan(s)`;
         $("#rows").innerHTML = d.scans.length ? d.scans.map((s) =>
           `<tr><td class="u">${esc(s.url)}</td><td>${badge(s.label)}</td><td>${s.risk_score}</td>
            <td>${when(s.created_at)}</td><td><button class="small" data-id="${s.id}">View</button></td></tr>`).join("")
           : `<tr><td colspan="5" class="muted">No scans yet. Scan a URL on the Home page.</td></tr>`;
       } catch (e) { $("#error").textContent = e.message; }
     }
     $("#rows").addEventListener("click", async (e) => {
       const id = e.target.dataset.id; if (!id) return;
       try { renderResult(await api("/history/" + id), $("#detail")); $("#detail").scrollIntoView({ behavior: "smooth" }); }
       catch (err) { $("#error").textContent = err.message; }
     });
     $("#clear").addEventListener("click", async () => {
       if (!confirm("Delete all scan history? This cannot be undone.")) return;
       try { await api("/history", { method: "DELETE" }); $("#detail").innerHTML = ""; load(); }
       catch (e) { $("#error").textContent = e.message; }
     });
     load();
   }