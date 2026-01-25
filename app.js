document.querySelector("#tarama").addEventListener("click", async () => {

  let url = getUrl(document.querySelector("#input").value.trim());
  let ip = await getIPFromDomain(url.hostname);

  console.log(`Tam URL : ${url.href}\nİP : ${ip}\nDomain : ${url.hostname}\nProtocol : ${url.protocol}`);

  isHTTPS(url);

  checkPhisng(url);

  domainDate(url.hostname);

  serverAndOrg(ip);
});

// URLyi alma fonksiyonu

function getUrl(inputValue) {
  try {
    if (!inputValue) {
      throw new Error("Lütfen girdiyi doldurun");
    } else if (!isValidURL(inputValue)) {
      throw new Error("Lütfen geçerli bir Link girin");
    }
    
    return new URL(inputValue);
  
  } catch (err) {
      console.log(`Hata : ${err.message}`);
      alert(err.message)
  };
};

function isValidURL(params) {
  try{
    new URL(params);
    return true
  } catch {
    return false 
  }
}

// TLS var mı yok mu onu kontrol eden fonksiyon
function isHTTPS(url) {
  try {
    const div =  document.querySelector("#ssl") 
    if(url.protocol === "https:"){
      div.style.borderColor="";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-primary/10 flex items-center justify-center mb-3 md:mb-4 border border-primary/20" 
      div.children[0].children[0].classList = "material-symbols-outlined text-primary text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-primary text-black text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvenli";
    } else if ( url.protocol === "http:"){
      div.style.borderColor="#DC143C";
      div.children[0].classList = "size-10 md:size-14 rounded-xl md:rounded-2xl bg-crimson/10 flex items-center justify-center mb-3 md:mb-4 border border-crimson/20"
      div.children[0].children[0].classList = "material-symbols-outlined text-crimson text-2xl md:text-3xl" 
      div.children[2].classList = "w-full md:w-auto px-2 md:px-4 py-1.5 rounded-full bg-crimson text-white text-[10px] md:text-xs font-black uppercase tracking-widest" 
      div.children[2].textContent="Güvensiz";
    } else {
      throw new Error("Bu bir web site linki değildir.")
    }

  } catch (err) {
    alert(err);
  }
}

// IP adresini bulan fonksiyon
async function getIPFromDomain(domain) {
  try {

    if (isIP(domain)) {
      console.log(domain);
      document.querySelector("#ip").textContent = domain;
      return domain;
    }

    let data = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    data = await data.json();

    if (data.Answer && data.Answer.length > 0) {
      const ip = data.Answer?.find(a => a.type === 1)?.data;
      if (!ip) {
        throw new Error("IPv4 (A kaydı) bulunamadı");
      }
      document.querySelector("#ip").textContent = ip;
      return ip;
    } else {
      throw new Error("Lütfen geçerli bir Link girin");
    }

  } catch (err) {
    alert(err);
  }
}

function isIP(ip) {
  return ip.split('.').every(octet => {
    const n = Number(octet);
    return n >= 0 && n <= 255 && octet === n.toString();
  });
}


// Phising kontrolü
async function checkPhisng(domain) {
  let new_data = await fetch(`https://api.phishstats.info/api/phishing?_where=(url,like,${domain})`);
  data = await new_data.json()
  const div = document.querySelector("#blacklist");
  if (data[0]) {
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

// Domainin Satın Alındığı Tarih
async function domainDate(domain) {
  try {
    let data = await fetch(`https://rdap.verisign.com/com/v1/domain/${domain}`);
    data = await data.json()
    const date =  new Date(data.events.find(e => ["registration", "created"].includes(e.eventAction)).eventDate);
    if (!date) {
      throw new Error("Domainin satın alındığı tarih bulunamadı");
    }
    const day  = Math.floor((new Date - date) / (1000 * 60 * 60 * 24))
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
  }catch (err) {
    alert(err)
  } 
}

// Sunucunun Konumu Ve Sağlayıcısı
async function serverAndOrg(ip) {
  try {
    let data = await fetch(`https://ipapi.co/${ip}/json/`);
    data = await data.json();
    document.querySelector("#saglayıcı").textContent = `${data.org}`
    document.querySelector("#ulke").textContent = `${data.country_name} ${data.country_code}`
    if (!data) {
      throw new Error("Hataa")
    }
  } catch (err) {
    alert(err);
  }
}



