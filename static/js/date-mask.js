(function () {
  "use strict";

  function digitsOnly(value) {
    return String(value || "").replace(/\D/g, "");
  }

  function maskDateBR(value) {
    const digits = digitsOnly(value).slice(0, 8);
    if (digits.length <= 2) return digits;
    if (digits.length <= 4) return digits.slice(0, 2) + "/" + digits.slice(2);
    return digits.slice(0, 2) + "/" + digits.slice(2, 4) + "/" + digits.slice(4);
  }

  function shouldMask(input) {
    if (!(input instanceof HTMLInputElement)) return false;
    if (input.type && input.type.toLowerCase() !== "text") return false;
    if (input.dataset.dateMask === "false") return false;
    if (input.dataset.dateMask === "true") return true;
    if (input.classList.contains("date-mask")) return true;
    const placeholder = (input.getAttribute("placeholder") || "").toLowerCase();
    const pattern = (input.getAttribute("pattern") || "").toLowerCase();
    return placeholder.includes("dd/mm") || pattern.includes("\\d{2}/\\d{2}/\\d{4}");
  }

  function applyMask(input) {
    const masked = maskDateBR(input.value);
    if (input.value !== masked) {
      input.value = masked;
    }
  }

  function bindInput(input) {
    if (!shouldMask(input) || input.dataset.dateMaskBound === "1") return;
    input.dataset.dateMaskBound = "1";
    input.setAttribute("maxlength", "10");
    input.setAttribute("inputmode", "numeric");
    applyMask(input);
    input.addEventListener("input", function () {
      applyMask(input);
    });
    input.addEventListener("paste", function () {
      setTimeout(function () {
        applyMask(input);
      }, 0);
    });
  }

  function scan(root) {
    const scope = root || document;
    scope.querySelectorAll("input").forEach(bindInput);
  }

  window.setupDateMasks = scan;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      scan(document);
    });
  } else {
    scan(document);
  }

  const observer = new MutationObserver(function (mutations) {
    mutations.forEach(function (mutation) {
      mutation.addedNodes.forEach(function (node) {
        if (!(node instanceof HTMLElement)) return;
        if (node.matches && node.matches("input")) {
          bindInput(node);
        }
        scan(node);
      });
    });
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
