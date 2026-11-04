"use strict";

(() => {
  const menu = document.querySelector(".site-menu");
  if (menu) {
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && menu.open) {
        menu.open = false;
        menu.querySelector("summary").focus();
      }
    });
    document.addEventListener("click", (event) => {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    });
  }

  const toggle = document.querySelector("[data-theme-toggle]");
  if (toggle) {
    toggle.hidden = false;
    const preference = window.matchMedia("(prefers-color-scheme: dark)");
    const isDark = () => document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : preference.matches;
    const updateLabel = () => {
      const label = isDark() ? "Switch to light appearance" : "Switch to dark appearance";
      toggle.setAttribute("aria-label", label);
      toggle.setAttribute("title", label);
    };
    updateLabel();
    toggle.addEventListener("click", () => {
      document.documentElement.dataset.theme = isDark() ? "light" : "dark";
      updateLabel();
    });
    preference.addEventListener("change", updateLabel);
  }

  const filter = document.querySelector("[data-resource-filter]");
  if (filter) {
    const input = filter.querySelector("input");
    const status = filter.querySelector("[role='status']");
    const resources = Array.from(document.querySelectorAll("[data-resource]"));
    filter.hidden = false;
    input.addEventListener("input", () => {
      const terms = input.value.toLocaleLowerCase("en-GB").trim().split(/\s+/).filter(Boolean);
      let count = 0;
      resources.forEach((resource) => {
        const text = resource.textContent.toLocaleLowerCase("en-GB");
        resource.hidden = !terms.every((term) => text.includes(term));
        if (!resource.hidden) count += 1;
      });
      status.textContent = count
        ? `${count} of ${resources.length} guides match.`
        : "No matching guides. Try pairing, firewall, SSH or installation.";
    });
  }
})();
