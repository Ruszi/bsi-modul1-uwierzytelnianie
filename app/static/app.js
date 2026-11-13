// Licznik do automatycznego wylogowania.
// To TYLKO podpowiedź dla użytkownika: właściwe wygaszenie sesji robi serwer
// (kolumna last_activity w tabeli sessions).
(function () {
  "use strict";
  var body = document.body;
  var idle = parseInt(body.getAttribute("data-idle-seconds") || "0", 10);
  var timer = document.getElementById("idle-timer");
  if (idle <= 0) return;                               // niezalogowany – nic nie robimy

  var deadline = Date.now() + idle * 1000;             // moment wylogowania
  function tick() {
    var left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    if (timer) {
      var m = Math.floor(left / 60), s = left % 60;
      timer.textContent = "Wylogowanie za " + m + ":" + (s < 10 ? "0" : "") + s;
    }
           if (Date.now() >= deadline + 2000) {               // +2 s zapasu, żeby serwer na pewno uznał sesję za wygasłą
      window.location.href = body.getAttribute("data-timeout-url");
      return;
    }
    setTimeout(tick, 1000);                            // sprawdzaj co sekundę
  }
  tick();
})();

// Potwierdzenie operacji nieodwracalnych (usuń, zablokuj, reset)
document.querySelectorAll("form[data-confirm]").forEach(function (form) {
  form.addEventListener("submit", function (e) {
    if (!window.confirm(form.getAttribute("data-confirm"))) {
      e.preventDefault();                       // "Anuluj" = nie wysyłaj formularza
    }
  });
});

// MODUŁ 2: odliczanie pozostałego czasu blokady konta na ekranie logowania
(function () {
  var el = document.getElementById("lock-timer");
  if (!el) return;
  var left = parseInt(el.getAttribute("data-seconds"), 10);
  function tick() {
    var m = Math.floor(left / 60), s = left % 60;
    el.textContent = m + ":" + (s < 10 ? "0" : "") + s;
    if (left <= 0) { el.textContent = "0:00 – możesz spróbować ponownie"; return; }
    left -= 1;
    setTimeout(tick, 1000);
  }
  tick();
})();