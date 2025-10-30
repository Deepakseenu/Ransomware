// Dashboard frontend - connects to your Flask backend
// Expects the following endpoints:
// GET  /api/events
// GET  /api/system_health
// GET  /api/stats_summary
// GET  /api/list_backup
// GET  /api/list_quarantine
// GET  /api/blocked_ips
// POST /api/block_ip   { ip: "1.2.3.4" }
// POST /api/unblock_ip { ip: "1.2.3.4" }
// GET  /api/process_list
// GET  /api/network_stats
// GET  /api/live_status

(() => {
  const socket = io();

  // Tabbing
  const navBtns = document.querySelectorAll(".nav-btn");
  const sections = document.querySelectorAll(".tab-section");
  function switchTab(name){
    navBtns.forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    sections.forEach(s => s.classList.toggle("active", s.id === name));
    // optional: lazy refresh per tab
    if(name === "blocked") loadBlocked();
    if(name === "backups") loadBackups();
    if(name === "quarantine") loadQuarantine();
    if(name === "system") loadSystem();
    if(name === "logs") loadLogs();
    if(name === "map") refreshMap();
  }
  navBtns.forEach(b => b.addEventListener("click", () => switchTab(b.dataset.tab)));

  // Theme toggle
  const themeBtn = document.getElementById("toggleTheme");
  function applyThemeFromStorage(){
    const t = localStorage.getItem("dashboard_theme") || "dark";
    document.documentElement.classList.toggle("light", t === "light");
  }
  themeBtn.addEventListener("click", () => {
    const isLight = document.documentElement.classList.toggle("light");
    localStorage.setItem("dashboard_theme", isLight ? "light" : "dark");
  });
  applyThemeFromStorage();

  // UI elements
  const activityStream = document.getElementById("activityStream");
  const liveEventsList = document.getElementById("liveEventsList");
  const socketStatus = document.getElementById("socketStatus");

  // Overview main numbers
  const totalEventsEl = document.getElementById("totalEvents");
  const totalBlockedEl = document.getElementById("totalBlocked");
  const totalQuarantineEl = document.getElementById("totalQuarantine");
  const totalBackupsEl = document.getElementById("totalBackups");
  const cpuEl = document.getElementById("cpu");
  const memoryEl = document.getElementById("memory");
  const uptimeEl = document.getElementById("uptime");

  // Blocked table controls
  const blockIpInput = document.getElementById("blockIpInput");
  const blockIpBtn = document.getElementById("blockIpBtn");
  const blockedTableBody = document.querySelector("#blockedTable tbody");

  // Backups / quarantine lists
  const backupList = document.getElementById("backupList");
  const quarantineList = document.getElementById("quarantineList");

  // System
  const procTableBody = document.querySelector("#procTable tbody");
  const sysCpu = document.getElementById("sysCpu");
  const sysMem = document.getElementById("sysMem");
  const netIo = document.getElementById("netIo");

  // Logs
  const logOutput = document.getElementById("logOutput");

  // Charts
  const eventsCtx = document.getElementById("eventsLine").getContext("2d");
  const eventsChart = new Chart(eventsCtx, {
    type: 'line',
    data: { labels: [], datasets: [{ label: 'Events', data: [], borderColor: '#00d1b2', backgroundColor: 'rgba(0,209,178,0.06)', fill: true }] },
    options: { responsive: true, animation: false, plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}} }
  });

  // Helpers
  function appendActivity(txt, cls){
    const div = document.createElement("div");
    div.className = "event-item";
    if(cls) div.classList.add(cls);
    div.textContent = `${new Date().toLocaleTimeString()} — ${txt}`;
    activityStream.prepend(div);
    liveEventsList.prepend(div.cloneNode(true));
    // cap length
    if(activityStream.childElementCount > 200) activityStream.lastChild.remove();
    if(liveEventsList.childElementCount > 300) liveEventsList.lastChild.remove();
  }

  // Loaders
  async function loadSummary(){
    try{
      const res = await fetch('/api/stats_summary');
      const data = await res.json();
      totalEventsEl.textContent = data.total_events ?? 0;
      totalBlockedEl.textContent = data.blocked_ips ?? 0;
      totalQuarantineEl.textContent = data.quarantine_count ?? 0;
      totalBackupsEl.textContent = data.backup_count ?? 0;
    }catch(err){
      console.warn("summary err", err);
    }
  }

  async function loadLiveStatus(){
    try{
      const res = await fetch('/api/live_status');
      const d = await res.json();
      cpuEl.textContent = (d.cpu ?? '—') + '%';
      memoryEl.textContent = (d.memory ?? '—') + '%';
      uptimeEl.textContent = d.uptime ?? '—';
      // push event to chart
      const t = new Date().toLocaleTimeString();
      eventsChart.data.labels.push(t);
      eventsChart.data.datasets[0].data.push(d.recent_events ?? 0);
      if(eventsChart.data.labels.length > 20){ eventsChart.data.labels.shift(); eventsChart.data.datasets[0].data.shift(); }
      eventsChart.update();
    }catch(e){ console.warn(e); }
  }

  async function loadBlocked(){
    try{
      const res = await fetch('/api/blocked_ips');
      const arr = await res.json();
      blockedTableBody.innerHTML = '';
      arr.forEach(entry=>{
        const tr = document.createElement('tr');
        const geo = entry.geo ? (entry.geo.city ? `${entry.geo.city}, ${entry.geo.country}` : entry.geo.country || '') : '—';
        const when = entry.last_blocked || '';
        tr.innerHTML = `<td>${entry.ip}</td><td>${geo}</td><td>${when}</td>
          <td><button class="btn small unblock" data-ip="${entry.ip}">Unblock</button></td>`;
        blockedTableBody.appendChild(tr);
      });
      // bind unblocks
      blockedTableBody.querySelectorAll('.unblock').forEach(btn=>{
        btn.addEventListener('click', async (e)=>{
          const ip = e.currentTarget.dataset.ip;
          try{
            const r = await fetch('/api/unblock_ip', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
            const j = await r.json();
            appendActivity(`Unblocked ${ip} — result: ${JSON.stringify(j)}`);
            await loadBlocked();
            await loadSummary();
          }catch(err){ appendActivity('Unblock failed: '+err.message); }
        });
      });
    }catch(err){ console.warn(err); }
  }

  async function blockIp(ip){
    try{
      const r = await fetch('/api/block_ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
      const j = await r.json();
      appendActivity(`Block IP ${ip} => ${JSON.stringify(j)}`);
      await loadBlocked();
      await loadSummary();
    }catch(err){ appendActivity('Block failed: '+err.message); }
  }

  blockIpBtn.addEventListener('click', () => {
    const ip = blockIpInput.value.trim();
    if(!ip) return alert('Enter an IP');
    blockIp(ip);
    blockIpInput.value = '';
  });

  async function loadBackups(){
    try{
      const res = await fetch('/api/list_backup');
      const arr = await res.json();
      backupList.innerHTML = '';
      arr.forEach(p=>{
        const li = document.createElement('li');
        li.textContent = p;
        backupList.appendChild(li);
      });
    }catch(e){ console.warn(e); }
  }

  async function loadQuarantine(){
    try{
      const res = await fetch('/api/list_quarantine');
      const arr = await res.json();
      quarantineList.innerHTML = '';
      arr.forEach(p=>{
        const li = document.createElement('li');
        li.textContent = p;
        quarantineList.appendChild(li);
      });
    }catch(e){ console.warn(e); }
  }

  async function loadSystem(){
    try{
      const res = await fetch('/api/system_health');
      const d = await res.json();
      sysCpu.textContent = (d.cpu ?? '—') + '%';
      sysMem.textContent = (d.memory ?? '—') + '%';
      // network stats
      const net = await (await fetch('/api/network_stats')).json();
      netIo.textContent = `sent:${(net.bytes_sent||0)} recv:${(net.bytes_recv||0)}`;
      // processes
      const procs = await (await fetch('/api/process_list')).json();
      procTableBody.innerHTML = '';
      procs.forEach(p=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${p.pid}</td><td>${p.name}</td><td>${(p.cpu_percent||0).toFixed(1)}</td><td>${(p.memory_percent||0).toFixed(1)}</td>`;
        procTableBody.appendChild(tr);
      });
    }catch(e){ console.warn('system load err', e); }
  }

  async function loadLogs(){
    try{
      const res = await fetch('/api/events');
      const arr = await res.json();
      logOutput.textContent = JSON.stringify(arr, null, 2);
    }catch(e){ console.warn(e); }
  }

  document.getElementById('refreshBtn').addEventListener('click', () => {
    loadAll();
  });

  document.getElementById('refreshBackups').addEventListener('click', loadBackups);
  document.getElementById('refreshQuarantine').addEventListener('click', loadQuarantine);
  document.getElementById('refreshSystem').addEventListener('click', loadSystem);
  document.getElementById('refreshLogs').addEventListener('click', loadLogs);
  document.getElementById('clearStream').addEventListener('click', () => {
    activityStream.innerHTML = '';
    liveEventsList.innerHTML = '';
  });

  // Map
  let map, markersLayer;
  function initMap(){
    if(map) return;
    map = L.map('mapContainer').setView([20,0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:18}).addTo(map);
    markersLayer = L.markerClusterGroup();
    map.addLayer(markersLayer);
  }
  async function refreshMap(){
    initMap();
    markersLayer.clearLayers();
    try{
      const res = await fetch('/api/blocked_ips');
      const arr = await res.json();
      arr.forEach(e=>{
        if(e.geo && e.geo.loc){
          const [lat,lon] = e.geo.loc.split(',');
          const m = L.marker([parseFloat(lat),parseFloat(lon)]).bindPopup(`<b>${e.ip}</b><br>${e.geo.city||''} ${e.geo.region||''} ${e.geo.country||''}`);
          markersLayer.addLayer(m);
        }
      });
    }catch(err){ console.warn(err); }
  }

  // Socket handlers
  socket.on('connect', () => {
    socketStatus.textContent = 'connected';
    socketStatus.style.color = '#8af';
  });
  socket.on('disconnect', () => {
    socketStatus.textContent = 'disconnected';
    socketStatus.style.color = '#f66';
  });
  socket.on('connect_error', (err) => {
    socketStatus.textContent = 'error';
    console.warn('socket error', err);
  });

  socket.on('new_event', (data) => {
    try{
      const info = (data && (data.info || data.type || JSON.stringify(data)));
      appendActivity(info);
      // update counters/overview live
      loadSummary();
    }catch(e){ console.warn(e); }
  });

  // Initial boot
  async function loadAll(){
    await loadSummary();
    await loadLiveStatus();
    await loadBlocked();
    await loadBackups();
    await loadQuarantine();
    await loadSystem();
    await loadLogs();
    await refreshMap();
  }

  loadAll();

  // periodic live status (every 8s)
  setInterval(loadLiveStatus, 8000);

  // expose for debugging
  window.__HONEY_DASH = { loadAll, loadBlocked, blockIp, refreshMap };
})();
