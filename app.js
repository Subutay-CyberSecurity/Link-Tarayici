document.querySelector("#tarama").addEventListener("click", async () => {

  let url = getUrl(document.querySelector("#input").value.trim());
  let ip = await getIPFromDomain(url.hostname);

  console.log(`Tam URL : ${url.href}\nİP : ${ip}\nDomain : ${url.hostname}\nProtocol : ${url.protocol}`);


  const httpsmi = isHTTPS(url);
  const blacklisttemi = await checkBlackList(url.hostname);
  const domuinintarihi = await domainDate(url.hostname);
  const ulkebilgisi = await serverAndOrg(ip);
  const tunnelmi = isTunnel(url.hostname);
//  const httpheaderi = await httpHeaders(url); 

  console.log("SSL :", httpsmi);
  console.log("black List :",blacklisttemi)
  console.log("domain kaç gün önce alındı :",domuinintarihi)
  console.log("Barındaırma bilgisi :",ulkebilgisi)
  console.log("tünelleme var mı : ",tunnelmi)
//  console.log("Http baslığı :",httpheaderi)
});

// URLyi alma fonksiyonu
function getUrl(inputValue) {
  try {
    if (!inputValue) {
      throw new Error("Lütfen girdiyi doldurun");
    }
    return new URL(inputValue);
  } catch (err) {
      console.log(`Hata : ${err.message}`);
      alert(err.message)
  };
};

// TLS var mı yok mu onu kontrol eden fonksiyon
function isHTTPS(url) {
    if(url.protocol === "https:") return true;
    if(url.protocol === "http:") return false;
    alert("Bu bir web site linki değildir");
}
/*
      const div =  document.querySelector("#ssl") 
      div.style.borderColor="";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-primary/10 flex items-center justify-center mb-3 md:mb-4 border border-primary/20" 
      div.children[0].children[0].classList = "material-symbols-outlined text-primary text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-primary text-black text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvenli"; */
///////////////////
/*      div.style.borderColor="#DC143C";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-crimson/10 flex items-center justify-center mb-3 md:mb-4 border border-crimson/20"
      div.children[0].children[0].classList = "material-symbols-outlined text-crimson text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-crimson text-white text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvensiz"; */


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
async function checkBlackList(domain) {
  let data = await fetch(`https://api.phishstats.info/api/phishing?_where=(url,like,${domain})`);
  data = await data.json()
  if (data[0]) return true;
  return false;
}
/*
      const div = document.querySelector("#blacklist");
      div.style.borderColor="#DC143C";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-crimson/10 flex items-center justify-center mb-3 md:mb-4 border border-crimson/20"
      div.children[0].children[0].classList = "material-symbols-outlined text-crimson text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-crimson text-white text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvensiz";
       
      div.style.borderColor="";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-primary/10 flex items-center justify-center mb-3 md:mb-4 border border-primary/20" 
      div.children[0].children[0].classList = "material-symbols-outlined text-primary text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-primary text-black text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvenli";
 */

// Domainin Satın Alındığı Tarih
async function domainDate(domain) {
  if (isTunnel(domain)) return false
  let data = await fetch(`https://rdap.verisign.com/com/v1/domain/${domain}`);
  if (!data) alert("Domainin satın alındığı tarih bulunamadı");
  data = await data.json()
  const date =  new Date(data.events?.find(e => ["registration", "created"].includes(e.eventAction)).eventDate);
  return Math.floor((new Date - date) / (1000 * 60 * 60 * 24));
}
/*
  const div = document.querySelector("#domainyas")
  div.classList = "text-base md:text-lg font-bold text-white"
  if (day < 7) {
    div.textContent = `${day} gün önce bu domain satın alındı`;
    div.classList = "text-base md:text-lg font-bold text-crimson"
  } else if (day < 30) {
    div.textContent = `${Math.floor(day / 7)} Hafta önce bu domain satın alındı`;
  } else if (day < 365) {
    div.textContent = `${Math.floor(day / 30)} Ay önce bu domain satın alındı`;
  } else {
    div.textContent = `${Math.floor(day / 365)} Yıl önce bu domain satın alındı`;
  } 
*/

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
//    document.querySelector("#saglayıcı").textContent = `${data.org}`
//    document.querySelector("#ulke").textContent = `${data.country_name} ${data.country_code}`
  } catch (err) {
    alert(err.message);
  }
}

//Tünelleme yapılıp yapılmadığını analiz eder
function isTunnel(domain) {
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
//    document.querySelector("#domainyas").textContent = "Tünelleme yapılıyor YÜKSEK RİSK";
//    document.querySelector("#domainyas").classList = "text-base md:text-lg font-bold text-crimson";


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
        contentLength : res.headers.get("content-length"),
        location: res.headers.get("location"),
        server: res.headers.get("server")
      }
    }
  }catch (err){
    alert(err)
  };
};
/*
    const analysis = {
      redirectRisk: headerJson.status >= 300 && headerJson.status < 400,
      downloadRisk: headerJson.headers.contentType?.includes("application"),
      hiddenServer: headerJson.headers.server === null,
      corsLimited: headerJson.type !== "basic"
    }
*/
