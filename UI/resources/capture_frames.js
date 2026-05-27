/**
 * 预渲染动画帧捕获脚本
 * 使用方法：node capture_frames.js
 * 输出：animation_frames.bin（原始 BGRA8 帧序列）
 *
 * 帧格式：
 *   [u32 LE] frame_count
 *   [u32 LE] frame_width
 *   [u32 LE] frame_height
 *   每帧: width * height * 4 bytes (BGRA8)
 *
 * 实现要点：
 *   - 用 Web Animations API 暂停 CSS 动画并精确寻址 currentTime，
 *     这样捕获节奏不受 page.screenshot() 真实耗时影响（每次截图约 30ms，
 *     无法靠 setTimeout 达到 240fps 的 4.17ms 间距）
 *   - PNG 直通 alpha 需要预乘后再写入，配合 D2D PREMULTIPLIED 表面
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

// CRITICAL: WIDTH/HEIGHT 必须与以下两处保持一致，运行时会 assert：
//   - animation_render.html body { width / height }
//   - Server/src/animation.rs ANIM_WIDTH / ANIM_HEIGHT
const WIDTH = 200;
const HEIGHT = 200;

// CRITICAL: DURATION_SECS 必须等于 animation.rs 的 FRAME_PERIOD
// falcon 设计只有 1s 旋转一个动画，1s 即可覆盖完整周期
const FPS = 240;
const DURATION_SECS = 1;
const TOTAL_FRAMES = FPS * DURATION_SECS; // 240 frames

async function main() {
    const { PNG } = require('pngjs');
    console.log(`Starting frame capture: ${WIDTH}x${HEIGHT} @ ${FPS}fps for ${DURATION_SECS}s = ${TOTAL_FRAMES} frames`);

    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu']
    });

    const page = await browser.newPage();
    await page.setViewport({ width: WIDTH, height: HEIGHT, deviceScaleFactor: 1 });

    const htmlPath = path.join(__dirname, 'animation_render.html');
    await page.goto('file://' + htmlPath, { waitUntil: 'networkidle0' });

    // 确保透明背景
    await page.evaluate(() => {
        document.documentElement.style.background = 'transparent';
        document.body.style.background = 'transparent';
    });

    // 等待 CSS 动画注册（getAnimations() 需要先有动画存在）
    await page.evaluate(() => new Promise(r => setTimeout(r, 200)));

    // 暂停所有 CSS 动画，以便后续逐帧精确寻址
    const animCount = await page.evaluate(() => {
        const anims = document.getAnimations();
        anims.forEach(a => a.pause());
        return anims.length;
    });
    if (animCount === 0) {
        throw new Error('页面没有任何 CSS 动画，无法逐帧捕获');
    }
    console.log(`  Paused ${animCount} animation(s) for deterministic seeking`);

    const outputPath = path.join(__dirname, 'animation_frames.bin');
    const fd = fs.openSync(outputPath, 'w');

    // 写入文件头
    const header = Buffer.alloc(12);
    header.writeUInt32LE(TOTAL_FRAMES, 0);
    header.writeUInt32LE(WIDTH, 4);
    header.writeUInt32LE(HEIGHT, 8);
    fs.writeSync(fd, header);

    const frameIntervalMs = 1000 / FPS;
    const startWall = Date.now();

    for (let i = 0; i < TOTAL_FRAMES; i++) {
        const animTimeMs = i * frameIntervalMs;

        // 把所有动画寻址到当前帧对应的时间点，不依赖真实墙钟
        await page.evaluate((t) => {
            for (const a of document.getAnimations()) {
                a.currentTime = t;
            }
            // 强制 reflow，确保下一次截图反映新状态
            void document.body.offsetHeight;
        }, animTimeMs);

        // 截图（omitBackground: true 保留透明度）
        const screenshot = await page.screenshot({
            type: 'png',
            omitBackground: true,
            clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT }
        });

        const pngBuffer = Buffer.from(screenshot);
        const png = PNG.sync.read(pngBuffer);

        // PNG 是 RGBA8 直通 alpha；D2D surface 用 D2D1_ALPHA_MODE_PREMULTIPLIED，
        // 必须把 RGB 预乘 alpha，否则半透明像素会渲染为白色光环
        const bgra = Buffer.alloc(WIDTH * HEIGHT * 4);
        for (let y = 0; y < HEIGHT; y++) {
            for (let x = 0; x < WIDTH; x++) {
                const srcIdx = (y * WIDTH + x) * 4;
                const dstIdx = (y * WIDTH + x) * 4;
                const r = png.data[srcIdx];
                const g = png.data[srcIdx + 1];
                const b = png.data[srcIdx + 2];
                const a = png.data[srcIdx + 3];
                bgra[dstIdx]     = Math.round(b * a / 255);
                bgra[dstIdx + 1] = Math.round(g * a / 255);
                bgra[dstIdx + 2] = Math.round(r * a / 255);
                bgra[dstIdx + 3] = a;
            }
        }

        fs.writeSync(fd, bgra);

        if ((i + 1) % 60 === 0 || i + 1 === TOTAL_FRAMES) {
            const elapsed = ((Date.now() - startWall) / 1000).toFixed(1);
            console.log(`  Captured ${i + 1}/${TOTAL_FRAMES} frames (${elapsed}s elapsed)`);
        }
    }

    fs.closeSync(fd);
    await browser.close();

    const fileSize = fs.statSync(outputPath).size;
    const totalSecs = ((Date.now() - startWall) / 1000).toFixed(1);
    console.log(`Done in ${totalSecs}s. Output: ${outputPath} (${(fileSize / 1024 / 1024).toFixed(1)} MB)`);
}

main().catch(err => {
    console.error('Capture failed:', err);
    process.exit(1);
});
