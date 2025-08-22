/* Demo PBKDF2 helpers for client-side auth */
function base64FromBytes(arr){
  return btoa(String.fromCharCode(...arr));
}
function bytesFromBase64(str){
  return new Uint8Array(atob(str).split("").map(c=>c.charCodeAt(0)));
}
function generateSalt(){
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return buf;
}
async function hashPassword(password, saltBase64){
  const salt = bytesFromBase64(saltBase64);
  const enc = new TextEncoder().encode(password);
  const key = await crypto.subtle.importKey("raw", enc, {name:"PBKDF2"}, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", salt, iterations:100000, hash:"SHA-256"}, key, 256);
  return base64FromBytes(new Uint8Array(bits));
}
