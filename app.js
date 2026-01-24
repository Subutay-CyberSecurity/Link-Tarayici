document.querySelector("#tarama").addEventListener("click", () => {

  url = getUrl(document.querySelector("#input").value.trim());
  console.log(`Tam URL : ${url.href}\nDomain : ${url.hostname}\nProtocol : ${url.protocol}`);

  isHTTPS(url);

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

    if(url.protocol === "https:"){
      console.log("Güvenli");
    } else if ( url.protocol === "http:"){
      console.log("Güvensiz");
    } else {
      throw new Error("Bu bir web site linki değildir.")
    }

  } catch (err) {
    alert(err);
  }
} 
