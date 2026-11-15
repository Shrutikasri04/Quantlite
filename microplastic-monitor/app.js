"use strict";

// Configure this only after the replacement backend contract has been verified.
const BACKEND_BASE_URL = "";

const routes = {
  overview: "Overview",
  "image-analysis": "Image analysis",
  "live-analysis": "Live analysis",
  map: "Monitoring map",
  analytics: "Analytics",
  reports: "Reports"
};

const views = [...document.querySelectorAll("[data-view]")];
const navLinks = [...document.querySelectorAll("[data-route]")];
const sidebar = document.querySelector(".sidebar");
const menuToggle = document.getElementById("menu-toggle");
let cameraStream = null;
let toastTimer;

function showRoute() {
  const candidate = window.location.hash.slice(1);
  const route = Object.hasOwn(routes, candidate) ? candidate : "overview";
  if (!window.location.hash || !Object.hasOwn(routes, candidate)) {
    history.replaceState(null, "", `#${route}`);
  }
  views.forEach((view) => { view.hidden = view.dataset.view !== route; });
  navLinks.forEach((link) => {
    const active = link.dataset.route === route;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  document.getElementById("crumb").textContent = routes[route];
  document.title = `${routes[route]} — QuantLite`;
  sidebar.classList.remove("open");
  menuToggle.setAttribute("aria-expanded", "false");
  menuToggle.setAttribute("aria-label", "Open navigation");
}

window.addEventListener("hashchange", showRoute);
showRoute();

menuToggle.addEventListener("click", () => {
  const open = sidebar.classList.toggle("open");
  menuToggle.setAttribute("aria-expanded", String(open));
  menuToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
});

function announce(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3000);
}

const imageInput = document.getElementById("image-file");
const dropzone = document.getElementById("dropzone");
const previewWrap = document.getElementById("preview-wrap");
const previewImage = document.getElementById("image-preview");
let previewUrl = null;

function previewFile(file) {
  if (!file) return;
  if (!file.type.startsWith("image/")) {
    announce("Choose an image file to preview.");
    return;
  }
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = URL.createObjectURL(file);
  previewImage.src = previewUrl;
  previewImage.alt = `Local preview of ${file.name}`;
  document.getElementById("file-meta").textContent = `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB`;
  dropzone.hidden = true;
  previewWrap.hidden = false;
}

imageInput.addEventListener("change", () => previewFile(imageInput.files[0]));
document.getElementById("remove-image").addEventListener("click", () => {
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  previewImage.removeAttribute("src");
  imageInput.value = "";
  previewWrap.hidden = true;
  dropzone.hidden = false;
});

for (const eventName of ["dragenter", "dragover"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragging");
  });
}
dropzone.addEventListener("drop", (event) => previewFile(event.dataTransfer.files[0]));

// Camera access is a browser-local preview only. No frames are sent or analyzed.
const cameraVideo = document.getElementById("camera-video");
const cameraEmpty = document.getElementById("camera-empty");
const cameraState = document.getElementById("camera-state");
const cameraStart = document.getElementById("camera-start");
const cameraStop = document.getElementById("camera-stop");

async function startCamera() {
  if (!navigator.mediaDevices?.getUserMedia) {
    document.getElementById("camera-message").textContent = "Camera preview is unavailable in this browser or page context. Try a secure localhost connection.";
    return;
  }
  cameraStart.disabled = true;
  cameraStart.textContent = "Requesting camera…";
  document.getElementById("camera-message").textContent = "Waiting for browser camera permission…";
  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
    cameraVideo.srcObject = cameraStream;
    cameraVideo.hidden = false;
    cameraEmpty.hidden = true;
    cameraState.textContent = "PREVIEW ACTIVE";
    cameraStart.disabled = true;
    cameraStart.textContent = "Preview active";
    cameraStop.disabled = false;
    document.getElementById("camera-message").textContent = "Local camera preview is active. No frames are being sent to a server.";
  } catch (error) {
    cameraState.textContent = "CAMERA OFF";
    cameraStart.disabled = false;
    cameraStart.textContent = "Start camera preview";
    const message = error.name === "NotAllowedError"
      ? "Camera permission was not granted. Allow access in your browser settings to preview locally."
      : "The camera could not be opened. Check that a camera is connected and not in use by another app.";
    document.getElementById("camera-message").textContent = message;
  }
}

function stopCamera() {
  cameraStream?.getTracks().forEach((track) => track.stop());
  cameraStream = null;
  cameraVideo.srcObject = null;
  cameraVideo.hidden = true;
  cameraEmpty.hidden = false;
  cameraState.textContent = "CAMERA OFF";
  cameraStart.disabled = false;
  cameraStart.textContent = "Start camera preview";
  cameraStop.disabled = true;
  document.getElementById("camera-message").textContent = "Camera preview stopped. No frames were sent to a server.";
}

cameraStart.addEventListener("click", startCamera);
cameraStop.addEventListener("click", stopCamera);
window.addEventListener("pagehide", () => {
  cameraStream?.getTracks().forEach((track) => track.stop());
  if (previewUrl) URL.revokeObjectURL(previewUrl);
});

// Integration gate: do not call a legacy endpoint or display unverified results.
// Once configured, verify health, request/response schema, labels, and units first.
if (BACKEND_BASE_URL.trim()) {
  document.getElementById("side-status").textContent = "Integration pending verification";
  document.getElementById("top-status").textContent = "Integration pending verification";
}
