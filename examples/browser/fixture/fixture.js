"use strict";

const increment = document.getElementById("increment");
const counter = document.getElementById("counter");
const reportTitle = document.getElementById("report-title");
const echo = document.getElementById("echo");

increment.addEventListener("click", () => {
  counter.textContent = String(Number(counter.textContent) + 1);
});

reportTitle.addEventListener("input", () => {
  echo.textContent = reportTitle.value;
});
