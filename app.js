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

// Analiz Fonksiyonu
function analysisfunc(cryptology, isBlackList, domainD, countryInfo, isTunnel, httpHeader) {
  let totalRisk = 0;
  let malwareRisk = 0;
  let phisingRisk = 0;


  document.querySelector("#saglayıcı").textContent = `${countryInfo.ISP}`
  document.querySelector("#ulke").textContent = `${countryInfo.countryName} ${countryInfo.countryCode}`
 

  if (!httpHeader) {
    console.log("sitede cors var");
  } else {
    totalRisk =- 5;
    malwareRisk =-5;
    phisingRisk =- 5;


    const httpAnalysis = {
      redirectRisk: headerJson.status >= 300 && headerJson.status < 400,
      downloadRisk: (
      contentType.includes("application/octet-stream") || 
      contentType.includes("application/zip") || 
      contentType.includes("application/x-msdownload") ||
      headers.disposition?.includes("attachment")
    ), 
      hiddenServer: headerJson.headers.server === null,
      corsLimited: headerJson.type !== "basic"
    }

    if (redirectRisk) {
      totalRisk =+ 20;
      malwareRisk =+ 10;
      phisingRisk =+ 10;
    } else {totalRisk =-5};

    if (httpAnalysis.downloadRisk) {
      totalRisk =+ 10;
      malwareRisk =+ 60;
      div.style.borderColor="#DC143C";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-crimson/10 flex items-center justify-center mb-3 md:mb-4 border border-crimson/20"
      div.children[0].children[0].classList = "material-symbols-outlined text-crimson text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-crimson text-white text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvensiz";     
    } else {
      malwareRisk =- 20;
      div.style.borderColor="";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-primary/10 flex items-center justify-center mb-3 md:mb-4 border border-primary/20" 
      div.children[0].children[0].classList = "material-symbols-outlined text-primary text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-primary text-black text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvenli"; 
    }
  }

  let div = document.querySelector("#domainyas")
  if(domainD === null){
    div.textContent = `Domain yası bulunamadı`;
    div.classList = "text-base md:text-lg font-bold text-crimson"
  } else if (domainD< 7) {
    div.textContent = `${domainD} gün önce bu domain satın alındı`;
    div.classList = "text-base md:text-lg font-bold text-crimson"
  } else if (domainD < 30) {
    div.textContent = `${Math.floor(domainD / 7)} Hafta önce bu domain satın alındı`;
    div.classList = "text-base md:text-lg font-bold text-white"
  } else if (domainD < 365) {
    div.textContent = `${Math.floor(domainD / 30)} Ay önce bu domain satın alındı`;
    div.classList = "text-base md:text-lg font-bold text-white"
  } else {
    div.textContent = `${Math.floor(domainD / 365)} Yıl önce bu domain satın alındı`;
    div.classList = "text-base md:text-lg font-bold text-white"
  } 

  if (isTunnel) {
    totalRisk =+ 50;
    malwareRisk =+ 50;
    phisingRisk =+ 50;
    document.querySelector("#domainyas").textContent = "Tünelleme yapılıyor YÜKSEK RİSK";
    document.querySelector("#domainyas").classList = "text-base md:text-lg font-bold text-crimson";
  }

  div =  document.querySelector("#ssl") 
  if (cryptology) {
    div.style.borderColor="";
    div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-primary/10 flex items-center justify-center mb-3 md:mb-4 border border-primary/20" 
    div.children[0].children[0].classList = "material-symbols-outlined text-primary text-2xl md:text-3xl" 
    div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-primary text-black text-[10px] md:text-xs font-black uppercase tracking-widest" 
    div.children[2].textContent="Güvenli"; 
  } else {
    totalRisk =+ 20;
    malwareRisk =+ 20;
    phisingRisk =+ 20
    div.style.borderColor="#DC143C";
    div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-crimson/10 flex items-center justify-center mb-3 md:mb-4 border border-crimson/20"
    div.children[0].children[0].classList = "material-symbols-outlined text-crimson text-2xl md:text-3xl" 
    div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-crimson text-white text-[10px] md:text-xs font-black uppercase tracking-widest" 
    div.children[2].textContent="Güvensiz";
  }

  div = document.querySelector("#blacklist");
  if (isBlackList) {
    totalRisk = 100;
    phisingRisk = 100;
    div.style.borderColor="#DC143C";
    div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-crimson/10 flex items-center justify-center mb-3 md:mb-4 border border-crimson/20"
    div.children[0].children[0].classList = "material-symbols-outlined text-crimson text-2xl md:text-3xl" 
    div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-crimson text-white text-[10px] md:text-xs font-black uppercase tracking-widest" 
    div.children[2].textContent="Güvensiz";
  } else {
    div.style.borderColor="";
    div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-primary/10 flex items-center justify-center mb-3 md:mb-4 border border-primary/20" 
    div.children[0].children[0].classList = "material-symbols-outlined text-primary text-2xl md:text-3xl" 
    div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-primary text-black text-[10px] md:text-xs font-black uppercase tracking-widest" 
    div.children[2].textContent="Güvenli";
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
  if (data.Answer && data.Answer.length > 0) return data.Answer?.find(a => a.type === 1)?.data; //Undifended veri gönderiyorsa dns kaynı yoktur yüksek risk
}

function isIP(ip) {
  return ip.split('.').every(octet => {
    const n = Number(octet);
    return n >= 0 && n <= 255 && octet === n.toString();
  });
}


// BlackList kontrolü
async function checkBlackList(url) {
  let data = await fetch(`https://api.phishstats.info/api/phishing?_where=(url,like,${url})`);
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

