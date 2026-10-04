// Set in mobile/.env.local (git-ignored). Use the laptop's Wi-Fi IP when running on a phone.
export const API_URL = process.env.EXPO_PUBLIC_API_URL ?? "http://127.0.0.1:8080";
export const API_TOKEN = process.env.EXPO_PUBLIC_API_TOKEN ?? "";
