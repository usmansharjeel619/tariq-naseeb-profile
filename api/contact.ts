type ContactPayload = {
  name?: unknown;
  company?: unknown;
  email?: unknown;
  phone?: unknown;
  country?: unknown;
  inquiry?: unknown;
  message?: unknown;
  honeypot?: unknown;
};

const MAX_BODY_BYTES = 4_500_000;
const MAX_ATTACHMENT_BYTES = 4_000_000;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const attachmentTypes = new Map([
  ["pdf", "application/pdf"],
  ["doc", "application/msword"],
  ["docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  ["png", "image/png"],
  ["jpg", "image/jpeg"],
  ["jpeg", "image/jpeg"],
]);

const json = (status: number, body: Record<string, string | boolean>) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });

function readText(value: unknown, label: string, { required = false, max = 160, min = 0 } = {}) {
  if (value === undefined || value === null) {
    if (required) throw new Error(`${label} is required.`);
    return "";
  }

  if (typeof value !== "string") throw new Error(`${label} is invalid.`);
  const text = value.trim();

  if (required && text.length < min) throw new Error(`${label} must be at least ${min} characters.`);
  if (text.length > max) throw new Error(`${label} must be ${max} characters or fewer.`);
  return text;
}

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  })[character] ?? character);
}

function escapeText(value: string) {
  return value.replace(/\r?\n/g, " ");
}

function toBase64(bytes: Uint8Array) {
  let binary = "";
  const chunkSize = 0x8000;

  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }

  return btoa(binary);
}

function isAllowedAttachment(file: File, bytes: Uint8Array) {
  const extension = file.name.split(".").pop()?.toLowerCase() ?? "";
  const expectedType = attachmentTypes.get(extension);
  if (!expectedType || file.type !== expectedType) return false;

  const header = bytes.slice(0, 8);
  if (extension === "pdf") return new TextDecoder().decode(header.slice(0, 5)) === "%PDF-";
  if (extension === "doc") return [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].every((value, index) => header[index] === value);
  if (extension === "docx") return [0x50, 0x4b, 0x03, 0x04].every((value, index) => header[index] === value);
  if (extension === "png") return [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((value, index) => header[index] === value);
  return header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff;
}

export default {
  async fetch(request: Request) {
    if (request.method !== "POST") return json(405, { ok: false, error: "Method not allowed." });

    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
      return json(413, { ok: false, error: "Inquiry is too large." });
    }

    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(request.url).origin) {
      return json(403, { ok: false, error: "Invalid form origin." });
    }

    let payload: ContactPayload;
    let attachment: { filename: string; content: string } | undefined;
    try {
      const formData = await request.formData();
      payload = {
        name: formData.get("name"),
        company: formData.get("company"),
        email: formData.get("email"),
        phone: formData.get("phone"),
        country: formData.get("country"),
        inquiry: formData.get("inquiry"),
        message: formData.get("message"),
        honeypot: formData.get("honeypot"),
      };

      const uploadedFile = formData.get("attachment");
      if (uploadedFile instanceof File && uploadedFile.size > 0) {
        if (uploadedFile.size > MAX_ATTACHMENT_BYTES) {
          return json(413, { ok: false, error: "The attachment must be 4 MB or smaller." });
        }

        const bytes = new Uint8Array(await uploadedFile.arrayBuffer());
        if (!isAllowedAttachment(uploadedFile, bytes)) {
          return json(400, { ok: false, error: "Attach a valid PDF, Word document, PNG, or JPEG file." });
        }

        attachment = {
          filename: uploadedFile.name.replace(/[^a-zA-Z0-9._ -]/g, "_") || "attachment",
          content: toBase64(bytes),
        };
      }
    } catch {
      return json(400, { ok: false, error: "Invalid request." });
    }

    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return json(400, { ok: false, error: "Invalid request." });
    }

    try {
      const honeypot = readText(payload.honeypot, "Honeypot", { max: 200 });
      if (honeypot) return json(200, { ok: true });

      const name = readText(payload.name, "Name", { required: true, min: 2, max: 100 });
      const company = readText(payload.company, "Company", { max: 120 });
      const email = readText(payload.email, "Email", { required: true, max: 254 });
      const phone = readText(payload.phone, "Phone", { max: 50 });
      const country = readText(payload.country, "Country", { max: 80 });
      const inquiry = readText(payload.inquiry, "Inquiry type", { required: true, min: 3, max: 120 });
      const message = readText(payload.message, "Message", { required: true, min: 10, max: 5_000 });

      if (!emailPattern.test(email)) return json(400, { ok: false, error: "Enter a valid email address." });

      const resendApiKey = process.env.RESEND_API_KEY;
      const recipient = process.env.CONTACT_TO_EMAIL;
      const sender = process.env.CONTACT_FROM_EMAIL;

      if (!resendApiKey || !recipient || !sender) {
        console.error("Contact form is missing required email configuration.");
        return json(503, { ok: false, error: "The inquiry service is temporarily unavailable. Please use WhatsApp or email us directly." });
      }

      const rows = [
        ["Name", name],
        ["Company", company],
        ["Email", email],
        ["Phone", phone],
        ["Country", country],
        ["Inquiry type", inquiry],
      ].filter(([, value]) => value);

      const textRows = rows.map(([label, value]) => `${label}: ${value}`).join("\n");
      const htmlRows = rows.map(([label, value]) => `<tr><td style="padding:6px 14px 6px 0;color:#5f6b7a;font-weight:600;vertical-align:top">${escapeHtml(label)}</td><td style="padding:6px 0;color:#111827">${escapeHtml(value)}</td></tr>`).join("");
      const safeMessage = escapeHtml(message).replace(/\r?\n/g, "<br />");

      const resendResponse = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: sender,
          to: [recipient],
          reply_to: email,
          subject: `[Tariq Naseeb Profile] ${escapeText(inquiry)} — ${escapeText(name)}`,
          text: `${textRows}\n\nMessage:\n${message}`,
          html: `<main style="max-width:640px;margin:0 auto;padding:32px;font-family:Arial,sans-serif"><p style="margin:0 0 8px;color:#0d5dcc;font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase">Tariq Naseeb profile inquiry</p><h1 style="margin:0 0 22px;color:#061225;font-size:24px">${escapeHtml(inquiry)}</h1><table style="border-collapse:collapse">${htmlRows}</table><div style="margin-top:26px;padding:18px 20px;border-left:3px solid #e31b2f;background:#f4f7fb;color:#111827;line-height:1.6">${safeMessage}</div></main>`,
          ...(attachment ? { attachments: [attachment] } : {}),
        }),
      });

      if (!resendResponse.ok) {
        console.error("Resend rejected a contact form email.", resendResponse.status);
        return json(502, { ok: false, error: "We could not send your inquiry. Please try again or use WhatsApp." });
      }

      return json(200, { ok: true });
    } catch (error) {
      if (error instanceof Error) return json(400, { ok: false, error: error.message });
      return json(400, { ok: false, error: "Invalid inquiry." });
    }
  },
};
