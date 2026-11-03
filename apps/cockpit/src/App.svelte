<script lang="ts">
  import { onMount } from 'svelte';

  interface PillarHealth {
    pillar: string;
    role: string;
    status: 'READY' | 'ONLINE' | 'DEGRADED' | 'OFFLINE';
    details: string;
    binary_path?: string;
    socket_path?: string;
    latency_ns?: number;
  }

  interface DaemonStatus {
    name: string;
    state: 'RUNNING' | 'STOPPED' | 'ERROR';
    pid?: number;
    target?: string;
    message: string;
  }

  let pillars: PillarHealth[] = [];
  let daemons: DaemonStatus[] = [];
  let connected = false;
  let activeTab: 'pillars' | 'daemons' | 'telemetry' = 'pillars';
  let logs: string[] = [];

  const API_BASE = 'http://127.0.0.1:9191';

  async function fetchDoctor() {
    try {
      const res = await fetch(`${API_BASE}/api/v1/doctor`);
      if (res.ok) {
        pillars = await res.json();
        connected = true;
      }
    } catch {
      connected = false;
    }
  }

  async function fetchDaemons() {
    try {
      const res = await fetch(`${API_BASE}/api/v1/daemons`);
      if (res.ok) {
        daemons = await res.json();
      }
    } catch {
      // offline
    }
  }

  async function triggerDaemon(name: string, action: 'start' | 'stop' | 'restart') {
    try {
      await fetch(`${API_BASE}/api/v1/daemons/${name.toLowerCase()}/${action}`, {
        method: 'POST'
      });
      await fetchDaemons();
      await fetchDoctor();
    } catch (e) {
      console.error(e);
    }
  }

  function startSSE() {
    const es = new EventSource(`${API_BASE}/api/v1/events`);
    es.addEventListener('connected', () => {
      connected = true;
      logs = [`[${new Date().toLocaleTimeString()}] Connected to Fabrial Telemetry Stream`, ...logs.slice(0, 50)];
    });
    es.addEventListener('update', (e) => {
      logs = [`[${new Date().toLocaleTimeString()}] ${e.data}`, ...logs.slice(0, 50)];
      fetchDaemons();
      fetchDoctor();
    });
    es.onerror = () => {
      connected = false;
    };
  }

  onMount(() => {
    fetchDoctor();
    fetchDaemons();
    startSSE();
    const interval = setInterval(() => {
      fetchDoctor();
      fetchDaemons();
    }, 3000);
    return () => clearInterval(interval);
  });
</script>

<div class="h-screen w-screen flex flex-col bg-slate-950 text-slate-100 font-sans select-none">
  <!-- Top Bar -->
  <header class="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800">
    <div class="flex items-center space-x-2">
      <span class="text-xl">💎</span>
      <div>
        <h1 class="text-sm font-semibold tracking-wide">Fabrial Cockpit</h1>
        <p class="text-[10px] text-slate-400">Sovereign AI Agent Security Fabric</p>
      </div>
    </div>
    <div class="flex items-center space-x-2">
      <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium {connected ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}">
        <span class="w-1.5 h-1.5 mr-1.5 rounded-full {connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}"></span>
        {connected ? 'CORE ONLINE' : 'FABRIAL OFFLINE'}
      </span>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <div class="flex bg-slate-900/50 border-b border-slate-800 px-4 text-xs font-medium">
    <button on:click={() => activeTab = 'pillars'} class="px-3 py-2 border-b-2 transition-colors {activeTab === 'pillars' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'}">
      10-Pillar Diagnostic Matrix
    </button>
    <button on:click={() => activeTab = 'daemons'} class="px-3 py-2 border-b-2 transition-colors {activeTab === 'daemons' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'}">
      Resident Daemons
    </button>
    <button on:click={() => activeTab = 'telemetry'} class="px-3 py-2 border-b-2 transition-colors {activeTab === 'telemetry' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'}">
      SIEM Telemetry & Events
    </button>
  </div>

  <!-- Main View -->
  <main class="flex-1 overflow-y-auto p-4 space-y-3">
    {#if activeTab === 'pillars'}
      <div class="grid grid-cols-2 gap-3">
        {#each pillars as p}
          <div class="p-3 bg-slate-900/70 border border-slate-800/80 rounded-lg flex flex-col justify-between hover:border-slate-700 transition">
            <div>
              <div class="flex items-center justify-between mb-1">
                <span class="font-semibold text-xs tracking-wide text-slate-200">{p.pillar}</span>
                <span class="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold {
                  p.status === 'ONLINE' || p.status === 'READY' ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800' :
                  p.status === 'DEGRADED' ? 'bg-amber-950/80 text-amber-400 border border-amber-800' :
                  'bg-rose-950/80 text-rose-400 border border-rose-800'
                }">
                  {p.status}
                </span>
              </div>
              <p class="text-[11px] text-slate-400 mb-1.5">{p.role}</p>
              <p class="text-[10px] text-slate-500 break-words leading-tight">{p.details}</p>
            </div>
            {#if p.latency_ns}
              <div class="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                <span>Latency</span>
                <span>{(p.latency_ns / 1_000_000).toFixed(2)} ms</span>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {:else if activeTab === 'daemons'}
      <div class="space-y-2">
        {#each daemons as d}
          <div class="p-3 bg-slate-900/70 border border-slate-800/80 rounded-lg flex items-center justify-between">
            <div>
              <div class="flex items-center space-x-2">
                <span class="font-semibold text-sm text-slate-200">{d.name}</span>
                <span class="text-[10px] px-1.5 py-0.2 rounded font-mono {d.state === 'RUNNING' ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-slate-400'}">
                  {d.state} {d.pid ? `(PID ${d.pid})` : ''}
                </span>
              </div>
              <p class="text-[11px] text-slate-400 mt-0.5">{d.message}</p>
              {#if d.target}
                <p class="text-[10px] text-slate-500 font-mono mt-0.5">{d.target}</p>
              {/if}
            </div>
            <div class="flex items-center space-x-1.5">
              {#if d.state === 'RUNNING'}
                <button on:click={() => triggerDaemon(d.name, 'restart')} class="px-2 py-1 text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition">Restart</button>
                <button on:click={() => triggerDaemon(d.name, 'stop')} class="px-2 py-1 text-[11px] bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded transition">Stop</button>
              {:else}
                <button on:click={() => triggerDaemon(d.name, 'start')} class="px-2 py-1 text-[11px] bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 rounded transition">Start</button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {:else if activeTab === 'telemetry'}
      <div class="h-full bg-slate-900 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-300 overflow-y-auto space-y-1">
        {#if logs.length === 0}
          <p class="text-slate-500 italic">Listening for live SIEM telemetry, Argus trips, and Locksmith leases...</p>
        {:else}
          {#each logs as log}
            <div class="leading-relaxed hover:text-white transition">{log}</div>
          {/each}
        {/if}
      </div>
    {/if}
  </main>
</div>
