
export async function generateIdenticon(seed: string): Promise<string> {
    // 1. Hash the seed (SHA-1)
    const msgBuffer = new TextEncoder().encode(seed);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // 2. Pick Color (first 3 bytes)
    // We want a nice color, so maybe limit brightness?
    // GitHub colors are usually saturation ~0.5-0.8.
    // Let's just use the bytes as RGB for simplicity, maybe ensure it's not too light.
    const r = hashArray[0];
    const g = hashArray[1];
    const b = hashArray[2];
    const color = `rgb(${r},${g},${b})`;
    
    // Background is usually light gray or white. Let's use specific gray f0f0f0.
    const bg = '#f0f0f0';

    // 3. Grid 5x5
    // We use bytes 3 to 17 (15 bytes) for the 5x5 grid? 
    // Actually standard identicon is 5x5, symmetric.
    // So we only need 3 columns x 5 rows = 15 bits/booleans.
    // We can use the next 15 bytes and check even/odd.
    
    const rects: string[] = [];
    let idx = 3; // start after color bytes

    for (let row = 0; row < 5; row++) {
        // Build a row of 5 cells (0,1,2, 3=1, 4=0)
        const rowData: boolean[] = [];
        for (let col = 0; col < 3; col++) {
            // Use byte at idx. If even/odd?
            // GitHub uses nibbles or specific bits.
            // Let's simply say: if byte % 2 === 0, it's colored.
            const byte = hashArray[idx % hashArray.length];
            rowData.push(byte % 2 === 0);
            idx++;
        }
        
        // Construct the full 5 cells for this row
        // col 0, 1, 2, 1, 0
        const cells = [rowData[0], rowData[1], rowData[2], rowData[1], rowData[0]];

        // Create rects
        for (let col = 0; col < 5; col++) {
            if (cells[col]) {
                // SVG rect
                // We'll assume a 50x50 viewBox, so each cell is 10x10.
                rects.push(`<rect x="${col * 10}" y="${row * 10}" width="10" height="10" fill="${color}" />`);
            }
        }
    }

    // 4. Construct SVG
    const svgContent = `
    <svg width="100" height="100" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg">
        <rect width="50" height="50" fill="${bg}" />
        ${rects.join('')}
    </svg>
    `.trim().replace(/\s+/g, ' '); // Minimal minification

    // 5. Base64 Encode
    // In Worker: btoa is available
    const base64 = btoa(svgContent);
    return `data:image/svg+xml;base64,${base64}`;
}
