let mode = "ssh", findings = [];
const $ = id => document.getElementById(id);

function setMode(m){ mode = m; $("tSsh").setAttribute("aria-pressed", m==="ssh"); $("tApa").setAttribute("aria-pressed", m==="apa"); }
$("tSsh").onclick = () => setMode("ssh");
$("tApa").onclick = () => setMode("apa");

function sample(){
  const L = [], pad = n => String(n).padStart(2,"0");
  if (mode === "ssh"){
    const users = ["root","admin","ubuntu","test","oracle","pi"];
    for (let i=0;i<14;i++) L.push(`Oct 26 03:${pad(10+i)}:${pad(i*3)} srv sshd[1201]: Failed password for ${i%3?"invalid user ":""}${users[i%6]} from 185.220.101.4 port ${40000+i} ssh2`);
    for (let i=0;i<6;i++) L.push(`Oct 26 04:0${i}:12 srv sshd[1302]: Failed password for root from 45.155.205.9 port ${50000+i} ssh2`);
    L.push("Oct 26 04:30:01 srv sshd[1400]: Failed password for sara from 10.0.0.8 port 51000 ssh2");
    L.push("Oct 26 04:31:44 srv sshd[1401]: Accepted password for sara from 10.0.0.8 port 51002 ssh2");
  } else {
    const a = (ip,t,p,s) => `${ip} - - [26/Oct/2026:05:${pad(t)}:00 +0000] "GET ${p} HTTP/1.1" ${s} 512 "-" "curl/8.0"`;
    ["/index.php?id=1'%20OR%201=1--","/item?id=1%20UNION%20SELECT%20user,pass%20FROM%20users","/search?q=1;sleep(5)"].forEach((p,i)=>L.push(a("91.240.118.7",i,p,200)));
    ["/download?f=../../etc/passwd","/img?f=%2e%2e%2f%2e%2e%2fetc/shadow"].forEach((p,i)=>L.push(a("203.0.113.50",10+i,p,403)));
    for (let i=0;i<18;i++) L.push(a("198.51.100.23",20+(i%30),`/admin${i}.php`,404));
    L.push(a("192.0.2.77",40,"/ping?host=8.8.8.8;cat%20/etc/passwd",200));
    L.push(a("10.0.0.8",41,"/index.html",200));
  }
  return L.join("\n");
}
$("sample").onclick = () => { $("log").value = sample(); };
$("file").onchange = e => { const f = e.target.files[0]; if (f) f.text().then(t => { $("log").value = t; }); };

// Detection helpers
function add(map, type, sev, ip, time){
  const k = type + "|" + ip;
  const f = map.get(k) || { type, severity: sev, sourceIp: ip, count: 0, firstSeen: time, lastSeen: time };
  f.count++; f.lastSeen = time; map.set(k, f);
}
function analyzeSsh(lines){
  const m = new Map(), re = /^(\w{3}\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?\S+ from ([\d.]+)/;
  lines.forEach(l => { const x = re.exec(l); if (x) add(m, "SSH Brute Force", "Medium", x[2], x[1]); });
  return [...m.values()].filter(f => f.count >= 5).map(f => (f.severity = f.count >= 10 ? "High" : "Medium", f));
}
function analyzeApache(lines){
  const m = new Map(), re = /^([\d.]+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3})/;
  const rules = [
    ["SQL Injection","High",/(union(\s|\+)+select|\bor\s+1=1|'\s*or\s*'|sleep\s*\(|information_schema)/i],
    ["Path Traversal","High",/(\.\.\/|\.\.\\)/],
    ["Command Injection","High",/(;|\||`|\$\()\s*(cat|ls|wget|curl|whoami|id|nc)\b/i]];
  const notFound = new Map();
  lines.forEach(l => {
    const x = re.exec(l); if (!x) return;
    const [, ip, time, , raw, status] = x;
    let p = raw; try { p = decodeURIComponent(raw.replace(/\+/g, " ")); } catch {}
    rules.forEach(([t, s, r]) => { if (r.test(p)) add(m, t, s, ip, time); });
    if (status === "404") add(notFound, "Scanning (404)", "Medium", ip, time);
  });
  const scans = [...notFound.values()].filter(f => f.count >= 15);
  return [...m.values(), ...scans];
}

const order = { High: 0, Medium: 1, Low: 2 };
function render(){
  $("result").hidden = false; $("aiOut").classList.remove("show");
  const c = s => findings.filter(f => f.severity === s).length;
  const ips = new Set(findings.map(f => f.sourceIp)).size;
  $("stats").innerHTML =
    `<div class="stat"><b>${findings.length}</b><span>نتيجة</span></div>` +
    `<div class="stat high"><b>${c("High")}</b><span>خطورة عالية</span></div>` +
    `<div class="stat med"><b>${c("Medium")}</b><span>خطورة متوسطة</span></div>` +
    `<div class="stat"><b>${ips}</b><span>IP مهاجم</span></div>`;
  const tb = $("rows"); tb.textContent = "";
  findings.forEach(f => {
    const tr = document.createElement("tr");
    [[f.type,""],[f.severity,"sev "+f.severity],[f.sourceIp,"ip"],[f.count,""],[f.firstSeen,"t"],[f.lastSeen,"t"]].forEach(([v, cls]) => {
      const td = document.createElement("td"); td.textContent = v; td.className = cls; tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  $("empty").hidden = findings.length > 0;
  $("ai").disabled = findings.length === 0;
}
$("go").onclick = () => {
  const lines = $("log").value.split("\n").filter(Boolean);
  if (!lines.length) { $("log").focus(); return; }
  findings = (mode === "ssh" ? analyzeSsh(lines) : analyzeApache(lines))
    .sort((a, b) => order[a.severity] - order[b.severity] || b.count - a.count);
  render();
};

// Local fallback so the preview still shows how the result looks
function localDemo(){
  const high = findings.filter(f => f.severity === "High").length;
  const risk = high ? "High" : "Medium";
  const top = [...new Set(findings.map(f => f.sourceIp))].slice(0, 3).join(", ");
  return `Risk level: ${risk}\nFindings: ${findings.length} (${high} high)\nTop source IPs: ${top}\nSuggested steps: block the IPs above at the firewall, enforce key-based SSH login, review WAF rules.`;
}
$("ai").onclick = async () => {
  const out = $("aiOut"), btn = $("ai");
  btn.disabled = true; out.classList.add("show"); out.textContent = "جاري التحليل...";
  try {
    const r = await fetch("/api/summarize", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ findings }) });
    const d = await r.json();
    out.textContent = r.ok ? d.summary : (d.error || "حصل خطأ");
  } catch {
    out.textContent = "";
    const tag = document.createElement("span"); tag.className = "tag";
    tag.textContent = "عرض تجريبي، مش AI حقيقي: الـ endpoint مش متوصل في المعاينة دي";
    out.append(tag, document.createTextNode("\n\n" + localDemo()));
  } finally { btn.disabled = false; }
};
$("tSsh").click(); $("log").value = sample(); $("go").click();
