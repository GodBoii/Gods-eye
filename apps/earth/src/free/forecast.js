/** Validate the bounded forecast fields the console displays. */
export function readForecast(payload) {
  const current = payload?.current;
  const hourly = payload?.hourly;
  if (!current || !['temperature_2m', 'relative_humidity_2m', 'wind_speed_10m'].every((key) => typeof current[key] === 'number' && Number.isFinite(current[key])) ||
    !Array.isArray(hourly?.temperature_2m) || hourly.temperature_2m.length < 24 || hourly.temperature_2m.length > 72 ||
    !hourly.temperature_2m.every((value) => typeof value === 'number' && Number.isFinite(value)) ||
    !Array.isArray(hourly.time) || hourly.time.length !== hourly.temperature_2m.length ||
    !hourly.time.every((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)))) throw new Error('Weather provider returned incomplete data.');
  return { temperature: current.temperature_2m, humidity: current.relative_humidity_2m, wind: current.wind_speed_10m,
    hours: hourly.temperature_2m.slice(0, 24), startsAt: hourly.time[0] };
}

export async function forecastAt({ lon, lat, signal }) {
  if (!Number.isFinite(lon) || Math.abs(lon) > 180 || !Number.isFinite(lat) || Math.abs(lat) > 90) throw new Error('Invalid weather coordinates');
  const params = new URLSearchParams({ longitude: lon.toFixed(2), latitude: lat.toFixed(2), current: 'temperature_2m,relative_humidity_2m,wind_speed_10m', hourly: 'temperature_2m', forecast_days: '1', timezone: 'GMT' });
  const response = await fetch(`https://api.open-meteo.com/v1/forecast?${params}`, { signal: AbortSignal.any([signal, AbortSignal.timeout(12000)].filter(Boolean)) });
  if (!response.ok) throw new Error(`Weather provider returned ${response.status}`);
  return readForecast(await response.json());
}
