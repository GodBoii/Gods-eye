import test from 'node:test';
import assert from 'node:assert/strict';
import { readForecast, forecastAt } from './forecast.js';

const payload = () => ({ current: { temperature_2m: 22, relative_humidity_2m: 50, wind_speed_10m: 10 }, hourly: { temperature_2m: Array(24).fill(20), time: Array.from({ length: 24 }, (_, i) => `2026-10-17T${String(i).padStart(2, '0')}:00`) } });
test('forecast preserves measurements and refuses incomplete or nonfinite provider data', () => {
  assert.equal(readForecast(payload()).temperature, 22);
  for (const invalid of [null, { current: {} }, { ...payload(), current: { ...payload().current, temperature_2m: null } }, { ...payload(), hourly: { temperature_2m: [NaN], time: ['invalid'] } }]) assert.throws(() => readForecast(invalid));
});
test('invalid weather coordinates fail before making network requests', async () => {
  await assert.rejects(forecastAt({ lon: 181, lat: 0 }), /Invalid weather coordinates/);
});
