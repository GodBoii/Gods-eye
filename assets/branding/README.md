# God's Eye identity

The orbital eye joins the security investigation workspace and Earth console.
The white mark on a dark square is shared by the app headers, loading screen,
browser favicons and mobile home-screen icons.

`godseye-master.png` is the original high-resolution artwork. The built-in
imagegen tool generated the concept and refined it on 19 October 2026.
The existing upstream SVG remains in Earth for source provenance; active brand
surfaces use this new artwork.

Final image prompt:

> Refine the God's Eye orbital eye into an immaculate flat app icon. Preserve
> the eye outline formed by two sweeping lids enclosing a planet with a diagonal
> orbit. Remove speckles, distressed texture, grunge, noise and stray pixels.
> Use clean solid white artwork on a uniform near-black background, no text,
> gradients, highlights or extra objects. Keep the mark centred and readable
> at small software-icon sizes.

After updating the master, regenerate the committed exports with:

```sh
node apps/earth/scripts/generate-icons.mjs
```

This uses Earth's existing Sharp dependency and writes identical files into
both frontends' `public/icons` directories and their `favicon.ico` files.
Exports include 16, 32, 48, 180, 192 and 512 pixel PNGs, a separate maskable
512 pixel icon, and an ICO containing 16, 32 and 48 pixel frames. PNG resizing
and ICO packaging are deterministic exports of the generated artwork.
