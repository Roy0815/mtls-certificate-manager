'use strict';

const env = require('../config/env');

/**
 * Uploads a file to a GoKapi instance via its REST API and returns the
 * one-time share link.
 *
 * API reference (verified against github.com/Forceu/Gokapi source,
 * internal/webserver/fileupload/FileUpload.go + internal/webserver/api/Api.go):
 *   POST {baseUrl}/api/files/add
 *   header: apikey: <key>
 *   multipart form fields: file, allowedDownloads, expiryDays, password
 *   response: { Result: "OK", FileInfo: { UrlDownload, Id, ... } }
 *
 * Note: GoKapi's public API only accepts expiry in whole days (expiryDays),
 * there is no hour-level parameter, so an hour-based config value is rounded
 * up to the nearest day.
 */
async function uploadFile(buffer, filename, { allowedDownloads, expiryHours }) {
  if (!env.GOKAPI_API_URL) {
    throw new Error('GOKAPI_API_URL is not configured');
  }
  if (!env.GOKAPI_API_KEY) {
    throw new Error('GOKAPI_API_KEY is not configured');
  }

  const expiryDays = Math.max(1, Math.ceil(expiryHours / 24));
  const form = new FormData();
  form.append('allowedDownloads', String(allowedDownloads));
  form.append('expiryDays', String(expiryDays));
  form.append('password', '');
  form.append('file', new Blob([buffer]), filename);

  const url = `${env.GOKAPI_API_URL.replace(/\/+$/, '')}/api/files/add`;
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { apikey: env.GOKAPI_API_KEY },
      body: form,
    });
  } catch (err) {
    // Never include the API key in an error that might get logged.
    throw new Error(`Could not reach GoKapi at the configured URL: ${err.message}`);
  }

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`GoKapi returned an unexpected response (HTTP ${res.status})`);
  }

  if (!res.ok || json.Result !== 'OK' || !json.FileInfo) {
    const detail = json.Message || json.Result || `HTTP ${res.status}`;
    throw new Error(`GoKapi upload failed: ${detail}`);
  }

  return {
    downloadUrl: json.FileInfo.UrlDownload,
    id: json.FileInfo.Id,
    expireAtString: json.FileInfo.ExpireAtString,
  };
}

module.exports = { uploadFile };
