export MODE="${MODE:-release}"

echo "Building $MODE wasm"

wasm-pack build --target web --$MODE
mv pkg/expander_symmetric_crypto_bg.wasm ../resources/expander/$MODE.wasm

mv pkg/expander_symmetric_crypto.js ../js/src/expander/wasm-binding.js
mv pkg/expander_symmetric_crypto.d.ts ../js/src/expander/wasm-binding.d.ts
