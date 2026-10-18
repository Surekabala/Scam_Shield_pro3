// ---------- Samples ----------
const SAMPLES = {
  scam: {
    name: "SBI Bank Support", email: "sbi-support@gmail.com",
    subject: "URGENT: Your account will be suspended within 24 hours",
    body: "Dear Customer,\n\nYour SBI account has been compromised. Verify now to avoid account suspension.\nClick to verify your identity immediately: http://sbi-secure-verify.xyz/login\nProvide OTP and enter your PIN to restore access. Final notice — act now before legal action is taken.\n\nSBI Support Team"
  },
  suspicious: {
    name: "HR Recruiter", email: "hr@globaljobs-india.top",
    subject: "Immediate joining bonus — work from home earn ₹50000",
    body: "Congratulations! You are selected for a work from home job with immediate joining bonus. Pay a small processing fee for loan-free placement. Limited time offer — respond within 24 hours.\nApply: bit.ly/job-apply-now"
  },
  safe: {
    name: "Amazon.in", email: "no-reply@amazon.in",
    subject: "Your order has been shipped",
    body: "Hi, your recent order #12345 has shipped and will arrive Tuesday. Track it on https://www.amazon.in/orders. Thank you for shopping with us."
  }
};

// ---------- Engine ----------
const RULES = [
  { cat: "Urgency Pressure", weight: 14, words: ["urgent","immediately","act now","final notice","limited time","within 24 hours","last chance","expires","suspended"] },
  { cat: "Credential Theft", weight: 16, words: ["click to verify","verify now","verify your identity","provide otp","enter your pin","password","confirm your account","otp","pin"] },
  { cat: "Threat / Legal", weight: 12, words: ["legal action","arrest","penalty","lawsuit","blocked"] },
  { cat: "Financial Scam", weight: 14, words: ["processing fee","bank details","wire transfer","claim now","lottery","you won","prize"] },
  { cat: "Job/Internship Scam", weight: 14, words: ["work from home earn","immediate joining bonus","joining bonus","registration fee","earn ₹","selected for a work from home"] },
  { cat: "Loan Scam", weight: 12, words: ["loan-free","processing fee for loan","instant loan","pre-approved loan","low interest loan"] }
];
const BAD_TLDS = [".xyz",".top",".click",".tk",".ml",".gq",".cf",".work",".icu"];
const SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy"];
const FREE_MAIL = ["gmail.com","yahoo.com","outlook.com","hotmail.com","proton.me"];
const OFFICIAL = ["bank","support","security","helpdesk","hr","recruiter","care","service","team"];
const BRANDS = { sbi:"sbi.co.in", hdfc:"hdfc.com", icici:"icici.com", amazon:"amazon.in", paypal:"paypal.com", google:"google.com", microsoft:"microsoft.com", netflix:"netflix.com" };

function analyze({ name, email, subject, body }) {
  const text = `${subject} ${body}`.toLowerCase();
  const found = [], cats = new Set();
  let score = 0;

  for (const r of RULES) {
    const hits = r.words.filter(w => new RegExp("(^|[^a-z0-9])" + w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "([^a-z0-9]|$)").test(text));
    if (hits.length) {
      cats.add(r.cat);
      score += Math.min(r.weight + (hits.length - 1) * 3, r.weight + 8);
      found.push({ lvl: r.cat === "Urgency Pressure" || r.cat === "Credential Theft" || r.cat === "Threat / Legal" ? "high" : "med",
        icon: "⚠️", msg: `${r.cat}: ${hits.slice(0, 3).map(h => `"${h}"`).join(", ")}` });
    }
  }

  // links
  const urls = (`${subject} ${body}`.match(/(?:https?:\/\/)?(?:[\w-]+\.)+[a-z]{2,}(?:\/[^\s]*)?/gi) || [])
    .filter(u => /^https?:/i.test(u) || SHORTENERS.some(s => u.toLowerCase().startsWith(s)) || BAD_TLDS.some(t => u.toLowerCase().includes(t)) || /\.(com|in|org|net)(\/|$)/i.test(u))
    .filter(u => !u.includes("@"));
  const links = [];
  const domainsSeen = new Set();
  for (const u of urls) {
    const host = u.replace(/^https?:\/\//i, "").replace(/^www\./i, "").split("/")[0].toLowerCase();
    if (domainsSeen.has(host)) continue; domainsSeen.add(host);
    let status = "VERIFIED", bad = false;
    const tld = BAD_TLDS.find(t => host.endsWith(t));
    if (SHORTENERS.includes(host)) { status = "SHORTENED"; bad = true; score += 12; found.push({ lvl: "med", icon: "🔗", msg: `Link risk — URL shortener conceals destination: ${host}` }); }
    else if (tld) { status = "FAKE TLD"; bad = true; score += 18; found.push({ lvl: "med", icon: "🔗", msg: `Link risk — Suspicious TLD "${tld}": ${host}` }); }
    else if (!u.startsWith("https")) { status = "NO HTTPS"; bad = true; score += 6; }
    links.push({ host, status, bad });
  }

  // sender
  const domain = (email.split("@")[1] || "").toLowerCase();
  const nm = name.toLowerCase();
  if (FREE_MAIL.includes(domain) && (OFFICIAL.some(o => nm.includes(o)) || Object.keys(BRANDS).some(b => nm.includes(b)))) {
    score += 14; cats.add("Sender Spoof");
    found.push({ lvl: "high", icon: "🛡️", msg: `Sender alert — official-sounding name from free provider (${domain})` });
  } else if (BAD_TLDS.some(t => domain.endsWith(t))) {
    score += 12; found.push({ lvl: "high", icon: "🛡️", msg: `Sender alert — suspicious sender domain (${domain})` });
  }

  // urgency amplifier
  const urgentCount = (text.match(/urgent|immediately|act now|final notice|within 24 hours|limited time/g) || []).length;
  if (urgentCount >= 3) { score += 10; found.push({ lvl: "med", icon: "⏰", msg: `High-pressure urgency language used ${urgentCount} times` }); }

  // brand impersonation
  for (const [b, real] of Object.entries(BRANDS)) {
    if ((nm.includes(b) || text.includes(b)) && domain && !domain.endsWith(real) && !domain.includes(b + ".")) {
      score += 10; found.push({ lvl: "high", icon: "🏷️", msg: `Brand impersonation — claims to be "${b}" but domain unverified` }); break;
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, found, links, cats: [...cats].slice(0, 4) };
}

// ---------- UI ----------
const $ = id => document.getElementById(id);
const C = 2 * Math.PI * 52;
let shown = 0, anim;

function setScore(target, color) {
  cancelAnimationFrame(anim);
  const from = shown, t0 = performance.now();
  (function step(t) {
    const k = Math.min(1, (t - t0) / 700);
    shown = Math.round(from + (target - from) * (1 - Math.pow(1 - k, 3)));
    $("score").textContent = shown;
    if (k < 1) anim = requestAnimationFrame(step);
  })(t0);
  const bar = $("bar");
  bar.style.strokeDashoffset = C * (1 - target / 100);
  bar.style.stroke = color;
}

function render() {
  const r = analyze({ name: $("sName").value, email: $("sEmail").value, subject: $("subject").value, body: $("body").value });
  let lvl = "safe", label = "Safe", color = "var(--green)", bg = "#e6f6ea", msg = "No significant threats detected.";
  if (r.score >= 60) { lvl = "danger"; label = "High Risk"; color = "var(--red)"; bg = "#ffe9ee"; msg = "High probability scam. Do not click links or share information."; }
  else if (r.score >= 30) { lvl = "warn"; label = "Suspicious"; color = "#f5b800"; bg = "#fff7dc"; msg = "Some warning signs found. Verify the sender before responding."; }

  setScore(r.score, color);
  document.querySelector(".ring-text").style.background = bg;
  const badge = $("badge"); badge.className = "badge " + lvl; badge.textContent = label;
  $("summary").textContent = msg;
  $("tags").innerHTML = r.cats.map(c => `<span class="tag">${c}</span>`).join("");

  $("details").innerHTML = r.found.length
    ? r.found.map((f, i) => `<div class="det ${f.lvl}" style="animation-delay:${i * 60}ms"><span>${f.icon}</span>${f.msg}</div>`).join("")
    : `<p class="muted">No threats detected. This email looks clean.</p>`;

  $("links").innerHTML = r.links.length
    ? r.links.map(l => `<div class="linkrow">${l.host}<span class="${l.bad ? "bad" : "ok"}">${l.status}</span></div>`).join("")
    : `<p class="muted">No links in this email.</p>`;
}

function load(key) {
  const s = SAMPLES[key];
  $("sName").value = s.name; $("sEmail").value = s.email; $("subject").value = s.subject; $("body").value = s.body;
  document.querySelectorAll(".chip").forEach(c => c.classList.toggle("active", c.dataset.sample === key));
  render();
}

document.querySelectorAll(".chip").forEach(c => c.addEventListener("click", () => load(c.dataset.sample)));
["sName", "sEmail", "subject", "body"].forEach(id => $(id).addEventListener("input", () => {
  document.querySelectorAll(".chip").forEach(c => c.classList.remove("active")); render();
}));

// scroll reveal
const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: .15 });
document.querySelectorAll(".reveal").forEach((el, i) => { el.style.transitionDelay = (i % 3) * 120 + "ms"; io.observe(el); });

// start with the safe sample, like the original
$("sName").value = SAMPLES.safe.name; $("sEmail").value = SAMPLES.safe.email;
$("subject").value = SAMPLES.safe.subject; $("body").value = SAMPLES.safe.body;
render();
