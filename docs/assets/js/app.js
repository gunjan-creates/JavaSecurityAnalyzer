(function () {
    "use strict";

    const subtle = window.crypto && window.crypto.subtle;
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();
    let downloadUrl;

    document.addEventListener("DOMContentLoaded", () => {
        updateCapabilityStatus();
        wirePasswordAnalyzer();
        wireTextEncryption();
        wireFileEncryption();
        writeBuildDate();
    });

    function updateCapabilityStatus() {
        const statusEl = document.getElementById("crypto-status");
        if (!statusEl) return;

        if (subtle) {
            statusEl.textContent = "Browser crypto ready: AES-GCM & PBKDF2 available.";
        } else {
            statusEl.textContent = "Web Crypto API unavailable. Encryption tools are disabled.";
            disableEncryptionSections();
        }
    }

    function disableEncryptionSections() {
        const buttons = document.querySelectorAll("#text-encryption button, #file-encryption button");
        buttons.forEach((btn) => {
            btn.disabled = true;
            btn.title = "Disabled because Web Crypto API is not supported in this browser.";
        });
    }

    function wirePasswordAnalyzer() {
        const form = document.getElementById("password-form");
        const input = document.getElementById("password-input");
        const toggleBtn = document.getElementById("toggle-password");
        const results = document.getElementById("password-results");
        const strengthBar = document.getElementById("strength-bar");
        const strengthLabel = document.getElementById("strength-label");
        const traitList = document.getElementById("trait-list");
        const suggestionList = document.getElementById("suggestion-list");

        if (!form || !input) return;

        form.addEventListener("submit", (event) => {
            event.preventDefault();
            const password = input.value.trim();
            if (!password) {
                results.hidden = true;
                return;
            }

            const analysis = analyzePassword(password);
            results.hidden = false;

            strengthBar.value = analysis.score;
            strengthLabel.textContent = `${analysis.score} / 100`;

            renderList(traitList, analysis.traits);
            renderList(suggestionList, analysis.suggestions);
        });

        toggleBtn.addEventListener("click", () => {
            const isHidden = input.getAttribute("type") === "password";
            input.setAttribute("type", isHidden ? "text" : "password");
            toggleBtn.textContent = isHidden ? "Hide" : "Show";
            toggleBtn.setAttribute("aria-pressed", String(isHidden));
            toggleBtn.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
        });
    }

    function analyzePassword(password) {
        const score = calculateScore(password);
        const traits = buildTraitList(password);
        const suggestions = buildSuggestions(password, score);
        return { score, traits, suggestions };
    }

    function calculateScore(password) {
        let score = 0;
        if (typeof zxcvbn === "function") {
            const result = zxcvbn(password);
            score = Math.min(100, result.score * 20 + Math.min(40, Math.max(0, password.length - 8) * 2));
            score = Math.max(score, Math.min(100, Math.round(result.guesses_log10 * 10)));
        } else {
            score = Math.min(100, password.length * 6);
        }

        if (/[A-Z]/.test(password)) score += 6;
        if (/[a-z]/.test(password)) score += 6;
        if (/[0-9]/.test(password)) score += 6;
        if (/[^A-Za-z0-9]/.test(password)) score += 6;

        return Math.min(100, score);
    }

    function buildTraitList(password) {
        const traits = [];
        traits.push(`Length: ${password.length} characters`);
        traits.push(/[A-Z]/.test(password) ? "Contains uppercase letters" : "No uppercase letters detected");
        traits.push(/[a-z]/.test(password) ? "Contains lowercase letters" : "No lowercase letters detected");
        traits.push(/[0-9]/.test(password) ? "Contains digits" : "No digits detected");
        traits.push(/[^A-Za-z0-9]/.test(password) ? "Contains special characters" : "No special characters detected");

        if (/(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
            traits.push("Includes sequential characters");
        }
        if (/(.)\1{2,}/.test(password)) {
            traits.push("Includes repeated characters");
        }
        if (/password|admin|user|welcome|qwerty|12345|letmein|dragon|football/i.test(password)) {
            traits.push("Matches a common pattern");
        }
        return traits;
    }

    function buildSuggestions(password, score) {
        const suggestions = [];
        if (password.length < 12) suggestions.push("Increase length to at least 12 characters.");
        if (!/[A-Z]/.test(password)) suggestions.push("Add uppercase letters.");
        if (!/[a-z]/.test(password)) suggestions.push("Add lowercase letters.");
        if (!/[0-9]/.test(password)) suggestions.push("Add numbers.");
        if (!/[^A-Za-z0-9]/.test(password)) suggestions.push("Add special symbols.");
        if (/(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
            suggestions.push("Avoid sequential characters like 123 or abc.");
        }
        if (/(.)\1{2,}/.test(password)) suggestions.push("Avoid repeating the same character three or more times.");
        if (/password|admin|user|welcome|qwerty|12345|letmein|dragon|football/i.test(password)) {
            suggestions.push("Avoid common words or default passwords.");
        }
        if (score < 60) {
            suggestions.push("Consider a passphrase made of unrelated words.");
            suggestions.push("Use a password manager for unique credentials.");
        }
        return suggestions.length ? suggestions : ["Strong password! Keep it unique and rotate regularly."];
    }

    function renderList(container, items) {
        if (!container) return;
        container.innerHTML = "";
        items.forEach((item) => {
            const li = document.createElement("li");
            li.textContent = item;
            container.appendChild(li);
        });
    }

    function wireTextEncryption() {
        const encryptBtn = document.getElementById("encrypt-text");
        const decryptBtn = document.getElementById("decrypt-text");
        const clearBtn = document.getElementById("clear-text");
        const inputEl = document.getElementById("text-input");
        const passwordEl = document.getElementById("text-password");
        const outputEl = document.getElementById("text-output");

        if (!encryptBtn || !decryptBtn) return;

        encryptBtn.addEventListener("click", async () => {
            if (!subtle) return;
            const text = inputEl.value;
            const password = passwordEl.value;
            outputEl.value = "";
            if (!text) {
                outputEl.value = "Enter text to encrypt.";
                return;
            }
            if (!password) {
                outputEl.value = "Password is required for encryption.";
                return;
            }
            try {
                const result = await encryptData(textEncoder.encode(text), password);
                outputEl.value = bufferToBase64(result);
            } catch (error) {
                outputEl.value = `Encryption failed: ${error.message}`;
            }
        });

        decryptBtn.addEventListener("click", async () => {
            if (!subtle) return;
            const password = passwordEl.value;
            const encrypted = (outputEl.value || "").trim() || inputEl.value.trim();
            if (!encrypted) {
                outputEl.value = "Provide encrypted data in the result field.";
                return;
            }
            if (!password) {
                outputEl.value = "Password is required for decryption.";
                return;
            }
            try {
                const bytes = base64ToBuffer(encrypted);
                const decrypted = await decryptData(bytes, password);
                inputEl.value = textDecoder.decode(decrypted);
                outputEl.value = "Decryption complete. Plaintext restored above.";
            } catch (error) {
                outputEl.value = `Decryption failed: ${error.message}`;
            }
        });

        clearBtn.addEventListener("click", () => {
            inputEl.value = "";
            outputEl.value = "";
            passwordEl.value = "";
        });
    }

    function wireFileEncryption() {
        const form = document.getElementById("file-encryption-form");
        if (!form || !subtle) return;

        const fileInput = document.getElementById("file-input");
        const passwordInput = document.getElementById("file-password");
        const encryptBtn = document.getElementById("encrypt-file");
        const decryptBtn = document.getElementById("decrypt-file");
        const statusEl = document.getElementById("file-status");
        const resultPanel = document.getElementById("file-results");
        const downloadLink = document.getElementById("download-link");

        const showStatus = (message, success = true) => {
            if (!statusEl || !resultPanel) return;
            statusEl.textContent = message;
            statusEl.style.color = success ? "var(--accent)" : "#f87171";
            resultPanel.hidden = false;
        };

        const resetDownload = () => {
            if (downloadUrl) {
                URL.revokeObjectURL(downloadUrl);
                downloadUrl = undefined;
            }
            if (downloadLink) {
                downloadLink.hidden = true;
                downloadLink.removeAttribute("href");
                downloadLink.removeAttribute("download");
            }
        };

        encryptBtn.addEventListener("click", async () => {
            resetDownload();
            if (!fileInput.files || !fileInput.files[0]) {
                showStatus("Select a file to encrypt.", false);
                return;
            }
            if (!passwordInput.value) {
                showStatus("Password required for encryption.", false);
                return;
            }

            const file = fileInput.files[0];
            try {
                const arrayBuffer = await file.arrayBuffer();
                const encryptedBytes = await encryptData(new Uint8Array(arrayBuffer), passwordInput.value);
                const blob = new Blob([encryptedBytes], { type: "application/octet-stream" });
                downloadUrl = URL.createObjectURL(blob);
                const suggestedName = `${file.name}.enc`;
                configureDownloadLink(downloadLink, downloadUrl, suggestedName);
                showStatus(`Encrypted ${file.name}. Keep your password safe.`, true);
            } catch (error) {
                showStatus(`Encryption failed: ${error.message}`, false);
            }
        });

        decryptBtn.addEventListener("click", async () => {
            resetDownload();
            if (!fileInput.files || !fileInput.files[0]) {
                showStatus("Select an encrypted file to decrypt.", false);
                return;
            }
            if (!passwordInput.value) {
                showStatus("Password required for decryption.", false);
                return;
            }

            const file = fileInput.files[0];
            try {
                const arrayBuffer = await file.arrayBuffer();
                const decrypted = await decryptData(new Uint8Array(arrayBuffer), passwordInput.value);
                const blob = new Blob([decrypted]);
                const suggestedName = file.name.replace(/\.enc$/i, "") || `${file.name}.decrypted`;
                downloadUrl = URL.createObjectURL(blob);
                configureDownloadLink(downloadLink, downloadUrl, suggestedName);
                showStatus(`Decrypted ${file.name}. Download and verify contents.`, true);
            } catch (error) {
                showStatus(`Decryption failed: ${error.message}`, false);
            }
        });

        form.addEventListener("reset", () => {
            resetDownload();
            if (resultPanel) resultPanel.hidden = true;
        });
    }

    function configureDownloadLink(link, url, filename) {
        if (!link) return;
        link.href = url;
        link.download = filename;
        link.hidden = false;
        link.textContent = `Download ${filename}`;
    }

    async function encryptData(data, password) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(password, salt);
        const buffer = data instanceof Uint8Array ? data : new Uint8Array(data);
        const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, buffer);
        const cipherBytes = new Uint8Array(ciphertext);
        return concatArrays([salt, iv, cipherBytes]);
    }

    async function decryptData(payload, password) {
        if (!(payload instanceof Uint8Array)) {
            payload = new Uint8Array(payload);
        }
        if (payload.length <= 28) {
            throw new Error("Payload too small or corrupted.");
        }
        const salt = payload.slice(0, 16);
        const iv = payload.slice(16, 28);
        const data = payload.slice(28);
        const key = await deriveKey(password, salt);
        const plaintext = await subtle.decrypt({ name: "AES-GCM", iv }, key, data);
        return new Uint8Array(plaintext);
    }

    async function deriveKey(password, salt) {
        const keyMaterial = await subtle.importKey(
            "raw",
            textEncoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );
        return subtle.deriveKey(
            {
                name: "PBKDF2",
                salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    function concatArrays(chunks) {
        const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        chunks.forEach((chunk) => {
            result.set(chunk, offset);
            offset += chunk.length;
        });
        return result;
    }

    function bufferToBase64(buffer) {
        if (!(buffer instanceof Uint8Array)) buffer = new Uint8Array(buffer);
        let binary = "";
        const chunkSize = 0x8000;
        for (let i = 0; i < buffer.length; i += chunkSize) {
            const chunk = buffer.subarray(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function base64ToBuffer(base64) {
        const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
        const padded = normalized + "===".slice((normalized.length + 3) % 4);
        const binary = atob(padded);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            buffer[i] = binary.charCodeAt(i);
        }
        return buffer;
    }

    function writeBuildDate() {
        const buildDateEl = document.getElementById("build-date");
        if (!buildDateEl) return;
        const now = new Date();
        buildDateEl.textContent = now.toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric"
        });
    }
})();
