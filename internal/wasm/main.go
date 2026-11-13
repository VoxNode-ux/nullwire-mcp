//go:build js && wasm

// Command wasm compiles the real NullWire scrubber to WebAssembly so the
// project page can show a live redactor. It adds no redaction rules of its
// own: the page calls exactly the code that the command line tool runs.
//
// Build it with scripts/build-wasm.sh.
package main

import (
	"syscall/js"

	"github.com/VoxNode-ux/nullwire-mcp/internal/app"
)

func main() {
	scrubber, err := app.NewScrubber()
	if err != nil {
		js.Global().Get("console").Call("error", "nullwire: "+err.Error())
		return
	}

	// nullwireScrub(text) returns {text, count}.
	js.Global().Set("nullwireScrub", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) == 0 {
			return map[string]any{"text": "", "count": 0}
		}
		out, n := scrubber.ScrubText(args[0].String())
		return map[string]any{"text": out, "count": n}
	}))

	// Tell the page the engine is ready, if it asked to be told.
	if ready := js.Global().Get("nullwireReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}

	select {} // keep the program alive so the function above stays callable
}