/** Inspect the viewer's existing context without creating a second canvas. */
export function readGraphicsStatus(canvas) {
  try {
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
    if (!gl) return { state: 'unavailable', renderer: null, preference: null };
    if (gl.isContextLost())
      return { state: 'lost', renderer: null, preference: null };
    const debug = gl.getExtension('WEBGL_debug_renderer_info');
    const renderer = gl.getParameter(
      debug ? debug.UNMASKED_RENDERER_WEBGL : gl.RENDERER,
    );
    return {
      state:
        /swiftshader|llvmpipe|softpipe|software|microsoft basic render/i.test(
          renderer || '',
        )
          ? 'software'
          : 'active',
      renderer: typeof renderer === 'string' && renderer ? renderer : null,
      preference: gl.getContextAttributes()?.powerPreference ?? null,
    };
  } catch {
    // Browser privacy policy or a resetting context may block inspection.
    return { state: 'unavailable', renderer: null, preference: null };
  }
}

export function graphicsStatusMessage(status) {
  if (status.state === 'lost')
    return 'Graphics context lost. Reload Earth to restart the renderer.';
  if (status.state === 'unavailable')
    return 'Renderer details are unavailable in this browser.';
  if (status.state === 'software')
    return 'Software renderer detected. Enable browser graphics acceleration and select the high-performance GPU in Windows Graphics settings, then restart the browser.';
  return 'High-performance GPU requested. Windows and the browser select the device; the renderer below identifies what is in use.';
}
