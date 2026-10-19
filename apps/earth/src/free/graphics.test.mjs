import assert from 'node:assert/strict';
import test from 'node:test';
import { readGraphicsStatus, graphicsStatusMessage } from './graphics.js';

function canvasFor(renderer, { debug = true, lost = false } = {}) {
  const gl = {
    RENDERER: 1,
    isContextLost: () => lost,
    getExtension: () => (debug ? { UNMASKED_RENDERER_WEBGL: 2 } : null),
    getParameter: (key) => (key === 2 ? renderer : 'WebKit WebGL'),
    getContextAttributes: () => ({ powerPreference: 'high-performance' }),
  };
  return { getContext: () => gl };
}

test('reports the active renderer rather than assuming the requested GPU was chosen', () => {
  for (const renderer of [
    'ANGLE (NVIDIA GeForce RTX 3050)',
    'ANGLE (AMD Radeon Graphics)',
  ]) {
    assert.deepEqual(readGraphicsStatus(canvasFor(renderer)), {
      state: 'active',
      renderer,
      preference: 'high-performance',
    });
  }
});

test('privacy-masked renderer stays usable without claiming NVIDIA selection', () => {
  const status = readGraphicsStatus(canvasFor('hidden', { debug: false }));
  assert.equal(status.renderer, 'WebKit WebGL');
  assert.equal(status.state, 'active');
  assert.doesNotMatch(graphicsStatusMessage(status), /NVIDIA|RTX/);
});

test('recognizes software rendering and gives actionable guidance', () => {
  for (const renderer of [
    'ANGLE (Google, Vulkan SwiftShader Device)',
    'llvmpipe',
    'Microsoft Basic Render Driver',
  ]) {
    const status = readGraphicsStatus(canvasFor(renderer));
    assert.equal(status.state, 'software');
    assert.match(graphicsStatusMessage(status), /graphics acceleration/);
  }
});

test('handles WebGL1, lost contexts, disabled WebGL and blocked diagnostics', () => {
  const canvas = canvasFor('NVIDIA');
  assert.equal(
    readGraphicsStatus({
      getContext: (type) => (type === 'webgl2' ? null : canvas.getContext()),
    }).renderer,
    'NVIDIA',
  );
  const lost = readGraphicsStatus(canvasFor('NVIDIA', { lost: true }));
  assert.equal(lost.state, 'lost');
  assert.match(graphicsStatusMessage(lost), /Reload/);
  assert.equal(
    readGraphicsStatus({ getContext: () => null }).state,
    'unavailable',
  );
  assert.equal(
    readGraphicsStatus({
      getContext: () => {
        throw new Error('blocked');
      },
    }).state,
    'unavailable',
  );
});
