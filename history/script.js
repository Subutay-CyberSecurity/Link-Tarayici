//  LOCALSTORAGE'DAN VERİYİ ÇEK
let history = JSON.parse(localStorage.getItem("history") || "[]");
totalSerch()
function totalSerch() {
  document.querySelector("#total").textContent = `${history.length}`
  const riskli_tarama = history.filter(e => e.risk >= 40).length;
  document.querySelector("#risk").textContent = `${riskli_tarama}`
}

const container = document.querySelector(".space-y-4");
container.innerHTML = "";

history.forEach((item, index) => {
  container.appendChild(createHistoryCard(item, index));
});

//  TÜM GEÇMİŞİ TEMİZLE BUTONU
document.querySelector("button").addEventListener("click", () => {
  history = [];
  localStorage.removeItem("history");
  container.innerHTML = "";
});

//  KART OLUŞTURMA FONKSİYONU
function createHistoryCard(e, index) {
  const card = document.createElement("div");
  card.className =
    "glass-card p-4 md:p-6 rounded-2xl md:rounded-3xl flex items-center gap-4 md:gap-8 group hover:border-crimson/40 transition-all duration-300 relative overflow-hidden";

  card.dataset.index = index;

  const riskColor =
    e.risk >= 70 ? "crimson" :
    e.risk >= 45 ? "yellow-500" :
    "emerald-500";

  card.innerHTML = `
    <div class="absolute left-0 top-0 w-1 h-full bg-${riskColor} opacity-0 group-hover:opacity-100 transition-opacity"></div>

    <div class="gauge-container shrink-0 relative">
      <svg class="w-12 h-12 md:w-16 md:h-16" viewBox="0 0 36 36">
        <path class="text-white/10 stroke-current"
          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831
             a 15.9155 15.9155 0 0 1 0 -31.831"
          fill="none" stroke-width="3"></path>

        <path class="text-${riskColor} stroke-current"
          stroke-dasharray="${e.risk}, 100"
          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831
             a 15.9155 15.9155 0 0 1 0 -31.831"
          fill="none" stroke-linecap="round" stroke-width="3"></path>
      </svg>

      <div class="absolute inset-0 flex items-center justify-center">
        <span class="text-xs font-black text-white">${e.risk}%</span>
      </div>
    </div>

    <div class="flex-1 min-w-0">
      <div class="flex items-center gap-2 mb-1">
        <span class="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
          ${e.time}
        </span>
        <span class="text-[10px] px-1.5 py-0.5 rounded bg-${riskColor}/20 text-${riskColor} font-black uppercase">
          ${e.risk >= 70 ? "KRİTİK" : e.risk >= 45 ? "TEHLİKELİ" : "GÜVENLİ"}
        </span>
      </div>

      <a href="${e.url}" target="_blank"
        class="text-primary font-bold text-base md:text-xl hover:text-white transition-colors truncate block">
        ${e.url}
      </a>
    </div>

    <div class="flex items-center gap-4">
      <div class="hidden md:block text-right">
        <span class="block text-[10px] font-bold text-slate-500 uppercase">Status</span>
        <span class="text-${riskColor} text-xs font-black uppercase">
          ${e.risk >= 70 ? "Zararlı" : e.risk >= 45 ? "Riskli" : "Zararsız"}
        </span>
      </div>

      <button class="delete-btn size-10 rounded-xl border border-white/5 hover:border-crimson/40 hover:bg-crimson/10 text-slate-500 hover:text-crimson flex items-center justify-center">
        <span class="material-symbols-outlined">close</span>
      </button>
    </div>
  `;

  return card;
}

//  TEK KAYIT SİL (DOM + LS)
container.addEventListener("click", e => {
  const btn = e.target.closest(".delete-btn");
  if (!btn) return;

  const card = btn.closest(".glass-card");
  const index = Number(card.dataset.index);

  history.splice(index, 1);
  localStorage.setItem("history", JSON.stringify(history));

  container.innerHTML = "";
  history.forEach((item, i) => {
    container.appendChild(createHistoryCard(item, i));
  });
  totalSerch()
});

