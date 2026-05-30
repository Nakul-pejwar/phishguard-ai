/* ═══════════════════════════════════════════
   PHISHGUARD AI — NEURAL NETWORK CONTROLLER
   Cybersecurity theme with neural animations
   ═══════════════════════════════════════════ */

const API_URL = "http://127.0.0.1:8000/api/check-url/";

// DOM Elements
const currentUrlEl = document.getElementById("currentUrl");
const scanBtn = document.getElementById("scanBtn");
const resultCard = document.getElementById("resultCard");
const errorText = document.getElementById("errorText");
const errorMsg = document.getElementById("errorMsg");

const statusIcon = document.getElementById("statusIcon");
const verdictText = document.getElementById("verdictText");
const riskText = document.getElementById("riskText");
const scoreText = document.getElementById("scoreText");
const scoreBar = document.getElementById("scoreBar");
const domainText = document.getElementById("domainText");
const rawScoreText = document.getElementById("rawScoreText");
const reasonsBox = document.getElementById("reasonsBox");

let activeUrl = "";

// ═══════════════════════════════════════════
// NEURAL NETWORK CANVAS ANIMATION
// ═══════════════════════════════════════════

class NeuralNetwork {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.nodes = [];
    this.connections = [];
    this.particles = [];
    this.mouseX = 0;
    this.mouseY = 0;
    this.frame = 0;
    this.resize();
    this.initNodes();
    this.bindEvents();
    this.animate();
  }

  resize() {
    const dpr = window.devicePixelRatio || 1;
    const rect = this.canvas.parentElement ? this.canvas.parentElement.getBoundingClientRect() : { width: 380, height: 600 };
    this.width = rect.width;
    this.height = Math.max(rect.height, 600);
    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.ctx.scale(dpr, dpr);
    this.canvas.style.width = this.width + 'px';
    this.canvas.style.height = this.height + 'px';
  }

  initNodes() {
    this.nodes = [];
    this.connections = [];

    const cols = 6;
    const rows = 10;
    const xGap = this.width / (cols + 1);
    const yGap = this.height / (rows + 1);

    // Create grid nodes
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const jitterX = (Math.random() - 0.5) * xGap * 0.5;
        const jitterY = (Math.random() - 0.5) * yGap * 0.5;
        this.nodes.push({
          x: (c + 1) * xGap + jitterX,
          y: (r + 1) * yGap + jitterY,
          baseX: (c + 1) * xGap + jitterX,
          baseY: (r + 1) * yGap + jitterY,
          r: Math.random() * 1.5 + 1,
          pulsePhase: Math.random() * Math.PI * 2,
          pulseSpeed: 0.01 + Math.random() * 0.02,
          opacity: 0.15 + Math.random() * 0.35,
          connections: []
        });
      }
    }

    // Create connections between nearby nodes
    for (let i = 0; i < this.nodes.length; i++) {
      for (let j = i + 1; j < this.nodes.length; j++) {
        const dx = this.nodes[i].x - this.nodes[j].x;
        const dy = this.nodes[i].y - this.nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const maxDist = Math.min(xGap, yGap) * 2.2;

        if (dist < maxDist && Math.random() > 0.55) {
          this.connections.push({
            from: i,
            to: j,
            opacity: 0.04 + Math.random() * 0.08,
            pulsePhase: Math.random() * Math.PI * 2,
            pulseSpeed: 0.005 + Math.random() * 0.015
          });
        }
      }
    }
  }

  bindEvents() {
    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      this.mouseX = e.clientX - rect.left;
      this.mouseY = e.clientY - rect.top;
    });

    this.canvas.addEventListener('mouseleave', () => {
      this.mouseX = -1000;
      this.mouseY = -1000;
    });

    window.addEventListener('resize', () => {
      this.resize();
      this.initNodes();
    });
  }

  spawnParticle() {
    if (this.particles.length > 15) return;
    if (this.connections.length === 0) return;

    const conn = this.connections[Math.floor(Math.random() * this.connections.length)];
    const fromNode = this.nodes[conn.from];
    const toNode = this.nodes[conn.to];

    this.particles.push({
      x: fromNode.x,
      y: fromNode.y,
      targetX: toNode.x,
      targetY: toNode.y,
      progress: 0,
      speed: 0.008 + Math.random() * 0.012,
      opacity: 0.6 + Math.random() * 0.4,
      size: 1 + Math.random() * 1.5
    });
  }

  draw() {
    this.ctx.clearRect(0, 0, this.width, this.height);
    this.frame++;

    // Draw connections
    for (const conn of this.connections) {
      const n1 = this.nodes[conn.from];
      const n2 = this.nodes[conn.to];

      const pulse = Math.sin(this.frame * conn.pulseSpeed + conn.pulsePhase) * 0.5 + 0.5;
      const opacity = conn.opacity * (0.5 + pulse * 0.5);

      this.ctx.beginPath();
      this.ctx.moveTo(n1.x, n1.y);
      this.ctx.lineTo(n2.x, n2.y);
      this.ctx.strokeStyle = `rgba(0, 212, 255, ${opacity})`;
      this.ctx.lineWidth = 0.5;
      this.ctx.stroke();
    }

    // Draw particles traveling along connections
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.progress += p.speed;

      if (p.progress >= 1) {
        this.particles.splice(i, 1);
        continue;
      }

      const x = p.x + (p.targetX - p.x) * p.progress;
      const y = p.y + (p.targetY - p.y) * p.progress;
      const fadeIn = Math.min(p.progress * 5, 1);
      const fadeOut = Math.min((1 - p.progress) * 5, 1);
      const alpha = p.opacity * fadeIn * fadeOut;

      this.ctx.beginPath();
      this.ctx.arc(x, y, p.size, 0, Math.PI * 2);
      this.ctx.fillStyle = `rgba(0, 212, 255, ${alpha})`;
      this.ctx.fill();

      // Glow
      this.ctx.beginPath();
      this.ctx.arc(x, y, p.size * 3, 0, Math.PI * 2);
      this.ctx.fillStyle = `rgba(0, 212, 255, ${alpha * 0.15})`;
      this.ctx.fill();
    }

    // Spawn new particles
    if (Math.random() < 0.08) {
      this.spawnParticle();
    }

    // Draw nodes
    for (const node of this.nodes) {
      // Mouse interaction - nodes gently repel from mouse
      const mdx = node.x - this.mouseX;
      const mdy = node.y - this.mouseY;
      const mDist = Math.sqrt(mdx * mdx + mdy * mdy);
      const interactRadius = 80;

      if (mDist < interactRadius) {
        const force = (interactRadius - mDist) / interactRadius;
        node.x += (mdx / mDist) * force * 2;
        node.y += (mdy / mDist) * force * 2;
      } else {
        // Spring back to base position
        node.x += (node.baseX - node.x) * 0.05;
        node.y += (node.baseY - node.y) * 0.05;
      }

      const pulse = Math.sin(this.frame * node.pulseSpeed + node.pulsePhase) * 0.5 + 0.5;
      const r = node.r * (0.8 + pulse * 0.4);
      const alpha = node.opacity * (0.5 + pulse * 0.5);

      // Node glow
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, r * 4, 0, Math.PI * 2);
      this.ctx.fillStyle = `rgba(0, 212, 255, ${alpha * 0.08})`;
      this.ctx.fill();

      // Node core
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
      this.ctx.fillStyle = `rgba(0, 212, 255, ${alpha})`;
      this.ctx.fill();
    }
  }

  animate() {
    this.draw();
    requestAnimationFrame(() => this.animate());
  }
}

// ═══════════════════════════════════════════
// PARTICLE BURST EFFECT
// ═══════════════════════════════════════════

function createParticleBurst(button) {
  const rect = button.getBoundingClientRect();
  const centerX = rect.left + rect.width / 2;
  const centerY = rect.top + rect.height / 2;

  for (let i = 0; i < 12; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';

    const angle = (Math.PI * 2 * i) / 12 + (Math.random() - 0.5) * 0.3;
    const distance = 40 + Math.random() * 60;
    const tx = Math.cos(angle) * distance;
    const ty = Math.sin(angle) * distance;

    particle.style.setProperty('--tx', tx + 'px');
    particle.style.setProperty('--ty', ty + 'px');
    particle.style.left = centerX + 'px';
    particle.style.top = centerY + 'px';
    particle.style.background = `hsl(${190 + Math.random() * 30}, 100%, ${60 + Math.random() * 20}%)`;

    document.body.appendChild(particle);
    setTimeout(() => particle.remove(), 800);
  }
}

// ═══════════════════════════════════════════
// TYPING EFFECT
// ═══════════════════════════════════════════

function typeEffect(element, text, speed = 40) {
  element.textContent = '';
  let i = 0;

  function type() {
    if (i < text.length) {
      element.textContent += text.charAt(i);
      i++;
      setTimeout(type, speed);
    }
  }
  type();
}

// ═══════════════════════════════════════════
// STATUS UI CONFIGURATION
// ═══════════════════════════════════════════

function getStatusUI(verdict) {
  if (verdict === "safe") {
    return {
      icon: "●",
      label: "SAFE",
      className: "safe",
      barColor: "linear-gradient(90deg, #00b894, #00e5a0)",
      glowColor: "rgba(0, 229, 160, 0.2)",
      ringColor: "#00e5a0"
    };
  }

  if (verdict === "suspicious") {
    return {
      icon: "●",
      label: "SUSPICIOUS",
      className: "suspicious",
      barColor: "linear-gradient(90deg, #f39c12, #ffb830)",
      glowColor: "rgba(255, 184, 48, 0.2)",
      ringColor: "#ffb830"
    };
  }

  return {
    icon: "●",
    label: "PHISHING DETECTED",
    className: "phishing",
    barColor: "linear-gradient(90deg, #e74c3c, #ff3860)",
    glowColor: "rgba(255, 56, 96, 0.2)",
    ringColor: "#ff3860"
  };
}

// ═══════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════

function setError(message) {
  errorMsg.textContent = message;
  errorText.classList.remove("hidden");
  errorText.style.animation = 'none';
  errorText.offsetHeight; // Trigger reflow
  errorText.style.animation = '';
}

function clearError() {
  errorText.classList.add("hidden");
  errorMsg.textContent = "";
}

function setLoading(isLoading) {
  scanBtn.disabled = isLoading;
  if (isLoading) {
    scanBtn.classList.add("scanning");
    scanBtn.querySelector('.btn-text').textContent = "SCANNING";
  } else {
    scanBtn.classList.remove("scanning");
    scanBtn.querySelector('.btn-text').textContent = "INITIATE SCAN";
  }
}

// ═══════════════════════════════════════════
// TAB & API FUNCTIONS
// ═══════════════════════════════════════════

async function getCurrentTabUrl() {
  const tabs = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  if (!tabs || tabs.length === 0) {
    throw new Error("No active tab found.");
  }

  return tabs[0].url || "";
}

async function scanUrl(url) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  });

  const data = await response.json();

  if (!response.ok || !data.success) {
    throw new Error(data.message || "Scan failed.");
  }

  return data.result;
}

// ═══════════════════════════════════════════
// RESULT RENDERING
// ═══════════════════════════════════════════

function renderResult(result) {
  const phishingScore = Number(result.phishing_probability || 0);
  const rawScore = Number(result.raw_phishing_probability || 0);

  const ui = getStatusUI(result.verdict);

  resultCard.classList.remove("hidden");

  // Reset animations
  resultCard.style.animation = 'none';
  resultCard.offsetHeight; // Trigger reflow
  resultCard.style.animation = 'cardAppear 0.5s cubic-bezier(0.16, 1, 0.3, 1)';

  // Update status icon color
  const statusSvg = statusIcon.querySelector('.status-svg');
  const statusRing = statusIcon.querySelector('.status-ring');
  const statusCore = statusIcon.querySelector('.status-core');

  statusSvg.style.color = ui.ringColor;
  statusRing.style.stroke = ui.ringColor;
  statusCore.style.fill = ui.ringColor;

  // Add glow animation to status
  statusIcon.style.filter = `drop-shadow(0 0 10px ${ui.glowColor}) drop-shadow(0 0 20px ${ui.glowColor})`;

  // Verdict with typing effect
  verdictText.textContent = ui.label;
  verdictText.className = `verdict ${ui.className}`;

  riskText.textContent = `RISK LEVEL: ${(result.risk_level || 'unknown').toUpperCase()}`;
  riskText.style.color = ui.ringColor;
  riskText.style.opacity = '0.8';

  // Animate score counter
  animateValue(scoreText, 0, phishingScore, 1000, "%");

  // Animate bar
  setTimeout(() => {
    scoreBar.style.width = `${phishingScore}%`;
    scoreBar.style.background = ui.barColor;
  }, 100);

  // Update bar glow
  const barGlow = document.querySelector('.bar-glow');
  if (barGlow) {
    barGlow.style.background = ui.barColor;
    barGlow.style.width = `${phishingScore}%`;
    barGlow.style.opacity = '0.5';
  }

  // Update bar nodes based on score
  updateBarNodes(phishingScore);

  domainText.textContent = result.domain || "-";
  rawScoreText.textContent = `${rawScore}%`;

  // Render reasons with staggered animation
  reasonsBox.innerHTML = "";

  if (result.reasons && result.reasons.length > 0) {
    result.reasons.forEach((reason, index) => {
      const div = document.createElement("div");
      div.className = "reason-item";
      div.style.animationDelay = `${0.3 + index * 0.1}s`;
      div.textContent = reason;
      reasonsBox.appendChild(div);
    });
  }
}

function animateValue(element, start, end, duration, suffix = "") {
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);

    // Easing function
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (end - start) * eased);

    element.textContent = `${current}${suffix}`;

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

function updateBarNodes(score) {
  const nodes = document.querySelectorAll('.bnode');
  nodes.forEach((node, index) => {
    const threshold = index * 25;
    if (score >= threshold) {
      node.classList.add('active');
    } else {
      node.classList.remove('active');
    }
  });
}

// ═══════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════

async function init() {
  try {
    clearError();
    activeUrl = await getCurrentTabUrl();

    // Type the URL with effect
    currentUrlEl.textContent = activeUrl;

    if (
      activeUrl.startsWith("chrome://") ||
      activeUrl.startsWith("edge://") ||
      activeUrl.startsWith("about:")
    ) {
      scanBtn.disabled = true;
      scanBtn.querySelector('.btn-text').textContent = "CANNOT SCAN";
      setError("This browser page cannot be scanned.");
    }
  } catch (error) {
    setError(error.message);
  }
}

// ═══════════════════════════════════════════
// EVENT LISTENERS
// ═══════════════════════════════════════════

scanBtn.addEventListener("click", async () => {
  try {
    clearError();
    setLoading(true);

    // Particle burst effect
    createParticleBurst(scanBtn);

    const result = await scanUrl(activeUrl);
    renderResult(result);
  } catch (error) {
    setError(error.message);
  } finally {
    setLoading(false);
  }
});

// ═══════════════════════════════════════════
// STARTUP
// ═══════════════════════════════════════════

// Initialize neural network canvas
const neuralCanvas = document.getElementById('neuralCanvas');
if (neuralCanvas) {
  new NeuralNetwork(neuralCanvas);
}

// Initialize app
init();
