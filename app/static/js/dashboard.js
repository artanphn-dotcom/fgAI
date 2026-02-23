const toolConfig = [
  { id: "home", title: "Dashboard" },
  { id: "dns-tools", title: "DNS Tools" },
  { id: "network-scanner", title: "Network Scanner" },
  { id: "ip-calculator", title: "IP Calculator" },
  { id: "port-scanner", title: "Port Scanner" },
  { id: "security-tools", title: "Security Tools" },
  { id: "subnet-visualizer", title: "Subnet Visualizer" },
  { id: "packet-analyzer", title: "Packet Analyzer" },
];

let currentScanPoll = null;

function byId(id) {
  return document.getElementById(id);
}

function setActivePanel(panelId) {
  document.querySelectorAll(".panel").forEach((panel) => panel.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach((btn) => btn.classList.remove("active"));

  const panel = byId(panelId);
  const nav = byId(`nav-${panelId}`);

  if (panel) panel.classList.add("active");
  if (nav) nav.classList.add("active");
}

function renderNav() {
  const navContainer = byId("nav-list");
  navContainer.innerHTML = "";

  for (const tool of toolConfig) {
    const button = document.createElement("button");
    button.className = "nav-btn";
    button.id = `nav-${tool.id}`;
    button.textContent = tool.title;
    button.onclick = () => setActivePanel(tool.id);
    navContainer.appendChild(button);
  }
}

function renderToolCards() {
  const grid = byId("dashboard-grid");
  grid.innerHTML = "";

  for (const tool of toolConfig.filter((item) => item.id !== "home")) {
    const card = document.createElement("div");
    card.className = "tool-card";
    card.innerHTML = `<h3>${tool.title}</h3><p>Open ${tool.title} module</p>`;
    card.onclick = () => setActivePanel(tool.id);
    grid.appendChild(card);
  }
}

async function apiPost(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }

  return data;
}

function setOutput(targetId, data, asTable = false) {
  const output = byId(targetId);
  if (!output) return;

  if (asTable && Array.isArray(data)) {
    output.innerHTML = "";
    if (!data.length) {
      output.textContent = "No data";
      return;
    }

    const headers = Object.keys(data[0]);
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");

    headers.forEach((header) => {
      const th = document.createElement("th");
      th.textContent = header;
      headRow.appendChild(th);
    });

    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    data.forEach((row) => {
      const tr = document.createElement("tr");
      headers.forEach((header) => {
        const td = document.createElement("td");
        const value = row[header];
        td.textContent = typeof value === "object" ? JSON.stringify(value) : String(value);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    output.appendChild(table);
    return;
  }

  if (typeof data === "string") {
    output.textContent = data;
    return;
  }

  output.textContent = JSON.stringify(data, null, 2);
}

function setError(targetId, error) {
  setOutput(targetId, `Error: ${error.message || error}`);
}

function bindDnsTools() {
  byId("dns-lookup-btn").onclick = async () => {
    try {
      setOutput("dns-output", "Loading...");
      const data = await apiPost("/api/dns/lookup", {
        domain: byId("dns-domain").value,
        record_type: byId("dns-record-type").value,
      });
      setOutput("dns-output", data);
    } catch (error) {
      setError("dns-output", error);
    }
  };

  byId("dns-reverse-btn").onclick = async () => {
    try {
      setOutput("dns-output", "Loading...");
      const data = await apiPost("/api/dns/reverse", {
        ip_address: byId("dns-reverse-ip").value,
      });
      setOutput("dns-output", data);
    } catch (error) {
      setError("dns-output", error);
    }
  };

  byId("dns-whois-btn").onclick = async () => {
    try {
      setOutput("dns-output", "Loading...");
      const data = await apiPost("/api/dns/whois", {
        domain: byId("dns-domain").value,
      });
      setOutput("dns-output", data);
    } catch (error) {
      setError("dns-output", error);
    }
  };

  byId("dns-propagation-btn").onclick = async () => {
    try {
      setOutput("dns-output", "Loading...");
      const data = await apiPost("/api/dns/propagation", {
        domain: byId("dns-domain").value,
        record_type: byId("dns-record-type").value,
      });
      setOutput("dns-output", data);
    } catch (error) {
      setError("dns-output", error);
    }
  };

  byId("dns-resolve-ip-btn").onclick = async () => {
    try {
      setOutput("dns-output", "Loading...");
      const data = await apiPost("/api/dns/resolve-ip", {
        domain: byId("dns-domain").value,
      });
      setOutput("dns-output", data);
    } catch (error) {
      setError("dns-output", error);
    }
  };
}

function bindNetworkScanner() {
  byId("network-scan-btn").onclick = async () => {
    try {
      if (currentScanPoll) {
        clearInterval(currentScanPoll);
      }

      setOutput("network-output", "Starting scan job...");
      byId("scan-progress-fill").style.width = "0%";
      byId("scan-progress-text").textContent = "0%";

      const startData = await apiPost("/api/network/scan/start", {
        target: byId("scan-target").value,
        ports: byId("scan-ports").value,
        timeout_seconds: Number(byId("scan-timeout").value || 0.8),
      });

      const jobId = startData.job_id;
      currentScanPoll = setInterval(async () => {
        const response = await fetch(`/api/network/scan/${jobId}`);
        const data = await response.json();

        if (!response.ok) {
          clearInterval(currentScanPoll);
          setOutput("network-output", data);
          return;
        }

        const progress = Number(data.progress || 0);
        byId("scan-progress-fill").style.width = `${progress}%`;
        byId("scan-progress-text").textContent = `${progress}% - ${data.message || "Running"}`;

        if (data.status === "completed") {
          clearInterval(currentScanPoll);
          setOutput("network-output", data.result);
        } else if (data.status === "failed") {
          clearInterval(currentScanPoll);
          setOutput("network-output", { error: data.error || "Scan failed" });
        }
      }, 1200);
    } catch (error) {
      setError("network-output", error);
    }
  };
}

function bindIpCalculator() {
  byId("ip-calc-btn").onclick = async () => {
    try {
      setOutput("ip-output", "Calculating...");
      const data = await apiPost("/api/ip/calculate", {
        network: byId("ip-network").value,
      });

      const rows = [
        { key: "IP Address", value: data.ip_address },
        { key: "CIDR", value: data.cidr },
        { key: "Subnet Mask", value: data.subnet_mask },
        { key: "Wildcard Mask", value: data.wildcard_mask },
        { key: "Network", value: data.network_address },
        { key: "Broadcast", value: data.broadcast_address },
        { key: "First Host", value: data.first_host },
        { key: "Last Host", value: data.last_host },
        { key: "Usable Hosts", value: data.usable_hosts },
      ];
      setOutput("ip-output", rows, true);

      const binaryOutput = {
        ip_binary: data.binary.ip,
        subnet_mask_binary: data.binary.subnet_mask,
        network_binary: data.binary.network,
        broadcast_binary: data.binary.broadcast,
      };
      setOutput("ip-binary-output", binaryOutput);
    } catch (error) {
      setError("ip-output", error);
      setOutput("ip-binary-output", "");
    }
  };

  byId("cidr-convert-btn").onclick = async () => {
    try {
      setOutput("ip-output", "Converting CIDR...");
      const data = await apiPost("/api/ip/cidr-mask", {
        cidr: Number(byId("ip-cidr").value),
      });
      setOutput("ip-output", data);
    } catch (error) {
      setError("ip-output", error);
    }
  };

  byId("vlsm-btn").onclick = async () => {
    try {
      setOutput("ip-output", "Building VLSM plan...");
      const hostRequirements = byId("vlsm-hosts")
        .value.split(",")
        .map((item) => Number(item.trim()))
        .filter((item) => Number.isFinite(item));

      const data = await apiPost("/api/ip/vlsm", {
        base_network: byId("vlsm-base-network").value,
        host_requirements: hostRequirements,
      });

      setOutput("ip-output", data.allocations, true);
    } catch (error) {
      setError("ip-output", error);
    }
  };
}

function bindPortScanner() {
  byId("port-scan-btn").onclick = async () => {
    try {
      setOutput("port-output", "Scanning ports...");
      const data = await apiPost("/api/security/port-status", {
        host: byId("port-host").value,
        ports: byId("port-list").value,
        timeout_seconds: Number(byId("port-timeout").value || 1),
      });
      setOutput("port-output", data.results, true);
    } catch (error) {
      setError("port-output", error);
    }
  };
}

function bindSecurityTools() {
  byId("banner-analyze-btn").onclick = async () => {
    try {
      setOutput("security-output", "Analyzing banner...");
      const data = await apiPost("/api/security/banner-analyze", {
        banner: byId("banner-input").value,
      });
      setOutput("security-output", data);
    } catch (error) {
      setError("security-output", error);
    }
  };

  byId("ssl-check-btn").onclick = async () => {
    try {
      setOutput("security-output", "Checking SSL certificate...");
      const data = await apiPost("/api/security/ssl-check", {
        hostname: byId("ssl-hostname").value,
        port: Number(byId("ssl-port").value || 443),
      });
      setOutput("security-output", data);
    } catch (error) {
      setError("security-output", error);
    }
  };

  byId("hash-btn").onclick = async () => {
    try {
      setOutput("security-output", "Generating hashes...");
      const data = await apiPost("/api/security/hash", {
        text: byId("hash-input").value,
      });
      setOutput("security-output", data);
    } catch (error) {
      setError("security-output", error);
    }
  };

  byId("password-check-btn").onclick = async () => {
    try {
      setOutput("security-output", "Checking password strength...");
      const data = await apiPost("/api/security/password-strength", {
        password: byId("password-input").value,
      });
      setOutput("security-output", data);
    } catch (error) {
      setError("security-output", error);
    }
  };
}

function bindSubnetVisualizer() {
  byId("subnet-visualize-btn").onclick = async () => {
    try {
      setOutput("subnet-output", "Building subnet visualization...");
      const data = await apiPost("/api/ip/calculate", {
        network: byId("subnet-network").value,
      });

      const text = [
        `Network: ${data.network_address}/${data.cidr}`,
        `Broadcast: ${data.broadcast_address}`,
        `Range: ${data.first_host} - ${data.last_host}`,
        `Hosts: ${data.usable_hosts}`,
        "",
        "Visualization:",
        `[${data.network_address}]---...---[${data.first_host} ... ${data.last_host}]---[${data.broadcast_address}]`,
      ].join("\n");

      setOutput("subnet-output", text);
    } catch (error) {
      setError("subnet-output", error);
    }
  };
}

function renderPacketAnalysis(data) {
  const summaryRows = [
    { key: "Issue Summary", value: data.issue_summary || "unknown" },
    { key: "Severity", value: data.severity || "unknown" },
    { key: "Root Cause", value: data.root_cause || "unknown" },
    { key: "Action Required", value: data.action_required || "unknown" },
    { key: "Firewall Policy", value: data.firewall_policy || "unknown" },
    { key: "Affected Hosts", value: (data.affected_hosts || []).join(", ") || "none" },
    { key: "Confidence", value: `${data.confidence_score ?? 0}%` },
  ];

  const recommendationRows = (data.recommendations || []).map((item, index) => ({
    step: index + 1,
    recommendation: item,
  }));

  const cliRows = (data.next_cli_checks || []).map((item, index) => ({
    step: index + 1,
    cli_check: item,
  }));

  setOutput("packet-summary-output", summaryRows, true);
  setOutput("packet-recommendations-output", recommendationRows, true);
  setOutput("packet-cli-output", cliRows, true);
  setOutput("packet-lines-output", (data.related_log_lines || []).join("\n") || "No related log lines returned.");
}

function bindPacketAnalyzer() {
  byId("packet-analyze-btn").onclick = async () => {
    try {
      const logs = byId("packet-logs").value || "";
      if (logs.trim().length < 20) {
        setOutput("packet-summary-output", "Provide at least 20 characters of FortiGate packet-sniffer logs.");
        setOutput("packet-recommendations-output", "");
        setOutput("packet-cli-output", "");
        setOutput("packet-lines-output", "");
        return;
      }

      setOutput("packet-summary-output", "Analyzing logs...");
      setOutput("packet-recommendations-output", "");
      setOutput("packet-cli-output", "");
      setOutput("packet-lines-output", "");

      const data = await apiPost("/analyze", { logs });
      renderPacketAnalysis(data);
    } catch (error) {
      setError("packet-summary-output", error);
      setOutput("packet-recommendations-output", "");
      setOutput("packet-cli-output", "");
      setOutput("packet-lines-output", "");
    }
  };
}

function init() {
  renderNav();
  renderToolCards();

  bindDnsTools();
  bindNetworkScanner();
  bindIpCalculator();
  bindPortScanner();
  bindSecurityTools();
  bindSubnetVisualizer();
  bindPacketAnalyzer();

  setActivePanel("home");
}

document.addEventListener("DOMContentLoaded", init);
