document.querySelector("#tarama").addEventListener("click", async () => {

  let url = getUrl(document.querySelector("#input").value.trim());
  let ip = await getIPFromDomain(url.hostname);
  document.querySelector("#ip").textContent = ip;
  const domain = url.hostname.replace(/^www\./, "");

  
  
  console.log(`Tam URL : ${url.href}\nİP : ${ip}\nDomain : ${domain}\nProtocol : ${url.protocol}`);


  const cryptology= isHTTPS(url);
  const isBlackList = await checkBlackList(url);
  const domainD = await domainDate(domain);
  const countryInfo = await serverAndOrg(ip);
  const isTunnel = checkTunnel(domain);
  const httpHeader = await httpHeaders(url); 

  analysisfunc(cryptology, isBlackList, domainD, countryInfo, isTunnel, httpHeader);

});

function analysisfunc(cryptology, isBlackList, domainD, countryInfo, isTunnel, httpHeader) {
  let totalRisk = 0;
  let malwareRisk = 0;
  let phisingRisk = 0;

  // Sağlayıcı ve Ülke Bilgileri
  document.querySelector("#saglayıcı").textContent = countryInfo?.ISP || "Bilinmiyor";
  document.querySelector("#ulke").textContent = countryInfo ? `${countryInfo.countryName} ${countryInfo.countryCode}` : "Bilinmiyor";

  // --- HTTP Header Analizi ---
  if (!httpHeader) {
    console.log("Sitede CORS var veya header alınamadı");
  } else {
    totalRisk -= 5;
    malwareRisk -= 5;
    phisingRisk -= 5;

    // Tanımlamaları httpHeader objesinden alalım
    const h = httpHeader.headers;
    const contentType = h.contentType?.toLowerCase() || "";

    const httpAnalysis = {
      redirectRisk: httpHeader.status >= 300 && httpHeader.status < 400,
      downloadRisk: (
        contentType.includes("application/octet-stream") || 
        contentType.includes("application/zip") || 
        contentType.includes("application/x-msdownload") ||
        h.disposition?.includes("attachment")
      ),
      hiddenServer: h.server === null,
      corsLimited: httpHeader.type !== "basic"
    };

    // Yönlendirme Kontrolü
    if (httpAnalysis.redirectRisk) {
      totalRisk += 40;
      malwareRisk += 20;
      phisingRisk += 35;
    }

    // İndirme (Malware) Analizi 
    if (httpAnalysis.downloadRisk) {
      totalRisk += 30;
      malwareRisk += 60;
      updateUI("malware", 3);
    } else {
      malwareRisk -= 20;
      updateUI("malware", 1);
    }
  }

  // --- Domain Yaşı Analizi ---
  let ageDiv = document.querySelector("#domainyas");
  if (domainD === null) {
    ageDiv.textContent = `Domain yaşı bulunamadı`;
    ageDiv.className = "text-base md:text-lg font-bold text-crimson";
    totalRisk += 10;
  } else {
    if (domainD < 7) {
      ageDiv.textContent = `${domainD} gün önce satın alındı (YENİ!)`;
      ageDiv.className = "text-base md:text-lg font-bold text-crimson";
      phisingRisk += 40; 
      totalRisk += 40;
      malwareRisk += 30;
    } else if (domainD < 30) {
      ageDiv.textContent = `${Math.floor(domainD / 7)} Hafta önce satın alındı`;
      ageDiv.className = "text-base md:text-lg font-bold text-white";
      phisingRisk += 10;
    } else {
      ageDiv.textContent = domainD > 365 ? `${Math.floor(domainD / 365)} Yıl önce satın alındı` : `${Math.floor(domainD / 30)} Ay önce satın alındı`;
      ageDiv.className = "text-base md:text-lg font-bold text-white";
    }
  }

  // --- Tünelleme Kontrolü ---
  if (isTunnel) {
    totalRisk += 60;
    phisingRisk += 90;
    ageDiv.textContent = "Tünelleme yapılıyor: YÜKSEK RİSK";
    ageDiv.className = "text-base md:text-lg font-bold text-crimson";
  }

  // --- SSL/HTTPS Kontrolü ---
  if (cryptology) {
    updateUI("ssl", 3);
  } else {
    totalRisk += 30;
    malwareRisk += 30;
    phisingRisk += 30;
    updateUI("ssl", 1);
  }

  // --- Blacklist Kontrolü ---
  if (isBlackList) {
    totalRisk = 100;
    phisingRisk = 100;
    updateUI("blacklist", 1);
  } else {
    updateUI("blacklist", 3);
  }
  if (malwareRisk >= 85) {
    totalRisk += 15;
    updateUI("malware" , 1)
  } else if (malwareRisk > 0) {
    totalRisk += 5;
    updateUI("malware", 2)
  } else {
    updateUI("malware", 3)
  }


  if (phisingRisk >= 85) {
    totalRisk += 15;
    updateUI("phishing" , 1)
  } else if (phisingRisk > 0) {
    totalRisk += 5;
    updateUI("phishing", 2)
  } else {
    updateUI("phishing", 3)
  }

  totalRisk = Math.min(100, Math.max(0, totalRisk));
  phisingRisk = Math.min(100, Math.max(0, phisingRisk));
  malwareRisk = Math.min(100, Math.max(0, malwareRisk));

  document.querySelector("#riskText").textContent = totalRisk;
  if (totalRisk >= 70) {
    document.querySelector("#text2").textContent = "İLERİ DÜZEY RİSK"
    document.querySelector("#riskCircle").classList = "text-crimson"
    document.querySelector("#text1").classList = "text-xs md:text-sm uppercase font-bold tracking-[0.2em] text-crimson mt-2"
    document.querySelector("#text2").classList = "text-3xl md:text-5xl font-display font-black text-crimson tracking-tighter mb-2"
  } else if (totalRisk >= 45){
    document.querySelector("#text2").textContent = "SÜPHELİ"
    document.querySelector("#riskCircle").classList = "text-warning"
    document.querySelector("#text1").classList = "text-xs md:text-sm uppercase font-bold tracking-[0.2em] text-warning mt-2"
    document.querySelector("#text2").classList = "text-3xl md:text-5xl font-display font-black text-warning tracking-tighter mb-2"
  } else {
    document.querySelector("#text2").textContent = "GÜVENLİ"
    document.querySelector("#riskCircle").classList = "text-primary"
    document.querySelector("#text1").classList = "text-xs md:text-sm uppercase font-bold tracking-[0.2em] text-primary mt-2"
    document.querySelector("#text2").classList = "text-3xl md:text-5xl font-display font-black text-primary tracking-tighter mb-2"
  }

  console.log(`Analiz Tamamlandı: Toplam Risk: ${totalRisk}, Phishing: ${phisingRisk}, Malware: ${malwareRisk}`);
}

// Yardımcı UI Fonksiyonu
function updateUI(id, riskLevel) {
    const element = document.querySelector(`#${id}`);
    if (!element) return;

    // riskLevel 0: GÜVENLİ (Turkuaz)
    // riskLevel 1: ŞÜPHELİ (Turuncu)
    // riskLevel 2: GÜVENSİZ (Kırmızı)

    if (riskLevel === 1) {
        // TEHLİKELİ / GÜVENSİZ
        element.style.borderColor = "#dc2626";
        element.children[0].className = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-crimson/10 flex items-center justify-center mb-3 md:mb-4 border border-crimson/20";
        element.children[0].children[0].className = "material-symbols-outlined text-crimson text-2xl md:text-3xl";
        element.children[2].className = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-crimson text-white text-[10px] md:text-xs font-black uppercase tracking-widest";
        element.children[2].textContent = "GÜVENSİZ";

    } else if (riskLevel === 2) {
        // ŞÜPHELİ 
        element.style.borderColor = "#f59e0b";
        element.children[0].className = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-warning/10 flex items-center justify-center mb-3 md:mb-4 border border-warning/20";
        element.children[0].children[0].className = "material-symbols-outlined text-warning text-2xl md:text-3xl";
        element.children[2].className = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-warning text-black text-[10px] md:text-xs font-black uppercase tracking-widest";
        element.children[2].textContent = "ŞÜPHELİ";

    } else if (riskLevel === 3){
        // GÜVENLİ
        element.style.borderColor = "";
        element.children[0].className = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-primary/10 flex items-center justify-center mb-3 md:mb-4 border border-primary/20";
        element.children[0].children[0].className = "material-symbols-outlined text-primary text-2xl md:text-3xl";
        element.children[2].className = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-primary text-black text-[10px] md:text-xs font-black uppercase tracking-widest";
        element.children[2].textContent = "GÜVENLİ";
    }
}

// URLyi alma fonksiyonu
function getUrl(inputValue) {
  try {
    if (!inputValue) {
      throw new Error("Lütfen girdiyi doldurun");
    }
    return new URL(inputValue);
  } catch (err) {
      alert(err.message)
  };
};

// TLS var mı yok mu onu kontrol eden fonksiyon
function isHTTPS(url) {
    if(url.protocol === "https:") return true;
    if(url.protocol === "http:") return false;
    alert("Bu bir web site linki değildir");
}


// IP adresini bulan fonksiyon
async function getIPFromDomain(domain) {
  if (isIP(domain)) return domain;
  let data = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
  data = await data.json();
  if (data.Answer && data.Answer.length > 0) return data.Answer?.find(a => a.type === 1)?.data;
}

function isIP(ip) {
  return ip.split('.').every(octet => {
    const n = Number(octet);
    return n >= 0 && n <= 255 && octet === n.toString();
  });
}


// BlackList kontrolü
async function checkBlackList(domain) {
  let data = await fetch(`https://api.phishstats.info/api/phishing?_where=(url,like,${domain})`);
  data = await data.json()
  if (data[0]) return true;
  return false;
}
      
// Domainin Satın Alındığı Tarih
async function domainDate(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`);
    if (!res.ok) return null;

    const data = await res.json();

    if (!Array.isArray(data.events)) return null;

    const ev = data.events.find(e =>
      e.eventAction === "registration" ||
      e.eventAction === "created"
    );

    if (!ev?.eventDate) return null;

    const d = new Date(ev.eventDate);
    return Math.floor((Date.now() - d) / 86400000);
  } catch {
    return null;
  }
}

// Sunucunun Konumu Ve Sağlayıcısı
async function serverAndOrg(ip) {
  try {
    let data = await fetch(`https://ipapi.co/${ip}/json/`);
    data = await data.json();
    if (!data) {throw new Error("Hataa")}
    return {
      countryName: data.country_name,
      countryCode: data.country_code,
      ISP: data.org
    };
  } catch (err) {
    alert(err.message);
  }
}

//Tünelleme yapılıp yapılmadığını analiz eder
function checkTunnel(domain) {
  const tunnelServices = [
  "trycloudflare.com",
  "ngrok.io",
  "ngrok-free.app",
  "ngrok.app",
  "ngrok.dev",
  "localtunnel.me",
  "loca.lt",
  "serveo.net",
  "localhost.run",
  "tunnelto.dev",
  "openport.io",
  "pagekite.me",
  "packetriot.net",
  "expose.sh",
  "replit.app",
  "repl.co",
  "glitch.me",
  "vercel.app",
  "netlify.app"
  ];

  if (tunnelServices.some(t => domain.endsWith(t))) return true
  return false;

};


// Header analiz
async function httpHeaders(url) {
  try {
    const res = await fetch(url, {
      method: "HEAD",
      redirect: "manual"
    });

    return {
      status: res.status,
      type: res.type,
      headers: {
        contentType: res.headers.get("content-type"),
        contentLength: res.headers.get("content-length"),
        location: res.headers.get("location"),
        server: res.headers.get("server"),
        disposition: res.headers.get("content-disposition"),
        security: res.headers.get("strict-transport-security"),
        poweredBy: res.headers.get("x-powered-by"),
        cookie: res.headers.get("set-cookie")
      }
    };
  } catch (err) {
    return false;
  }
}

