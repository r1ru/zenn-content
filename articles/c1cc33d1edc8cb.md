---
title: "WasmOS: Wasmを実行する自作マイクロカーネル"
emoji: "🦅"
type: "tech"
topics:
  - "wasm"
  - "自作os"
  - "低レイヤ"
published: true
published_at: "2024-01-07 15:54"
---

# 背景
WebAssembly(Wasm)をブラウザの外で活用するために[WASI](https://wasi.dev/)の標準化が進められています。その目的は隔離され、制限されたWasmの実行環境を作ることですが、これは難しい挑戦です。WASMの安全性は外部APIの能力に依存するため、WASIの標準化は慎重に行う必要がありますが、これには多くの時間がかかります。私はこれが[WASIX](https://wasix.org/)や[WALI](https://arxiv.org/abs/2312.03858)といった新しいシステムインタフェースが登場した原因の一つであると考えています。汎用だったはずのWasmバイナリは既にランタイム依存になりつつあります。

WASIでセキュリティを考え、苦労して「第二のOS」を作る必要があるという事実は、既存のOSが今の時代に即したものでないことを示唆します。**ならばいっそ、新しいOSを作ってしまうのはどうでしょう？** この記事ではWasmを実行する自作マイクロカーネルである、WasmOSを紹介します。

# WasmOS

![logo](https://storage.googleapis.com/zenn-user-upload/020c8740cac6-20240204.png)

https://github.com/r1ru/WasmOS

WasmOSは私が[HinaOS](https://github.com/nuta/microkernel-book)をベースに開発している自作マイクロカーネルです。カーネルはWasmバイナリからタスクを生成する[システムコール](https://github.com/r1ru/WasmOS/blob/main/kernel/syscall.c#L110-L140)を持っており、Wasmランタイムとして[WAMR](https://github.com/bytecodealliance/wasm-micro-runtime)を用いることでWasmを直接実行することができます。簡単なWebサーバー(Wasmバイナリ)が動く程度の完成度です。

![wasmos_shell](https://storage.googleapis.com/zenn-user-upload/b4458a253632-20231231.png)

# 特徴
## Portable
マイクロカーネルの基本はsend, receiveを用いたメッセージパッシングです。WasmOSはWasmバイナリにipc_{lookup, recv, reply, call}という4つのメッセージパッシング用のAPIを提供しています。(たった4つです!!)入力を受け取り(receive)、結果を出力する(send)というのはプログラムの姿そのものであるため、このシステムインタフェースはOS非依存で、かつ必要最小限なものになっています。これはWASIにはない特徴です。

https://github.com/r1ru/WasmOS/blob/main/kernel/wasmvm.c#L102-L108

自作OSの問題点としてバイナリが自作OSでしか動作しないことが挙げられますが、WasmOSの場合、LinuxやWindowsといった既存のOSでもWasmランタイムとサーバーの実装を用意すれば**同じバイナリ**を動かすことができます。重要なのはそれぞれの環境にあった抽象度でサーバーを実装できる点です。例えばWasmos上で動いている[wasm_webapiサーバー](https://github.com/r1ru/WasmOS/blob/main/servers/wasm_webapi)は[tcpipサーバー](https://github.com/r1ru/WasmOS/blob/main/servers/tcpip)の実装を必要とします。WasmOSはベアメタル環境で動作するため、tcpipサーバーは[virtio_netサーバー](https://github.com/r1ru/WasmOS/blob/main/servers/virtio_net)というデバイスドライバサーバーを必要としますが、Linux環境ではtcpipサーバーを普通のsocket APIを用いて実装できます。

## Safe
Wasmバイナリは実行前に検証され、型の整合性や未定義の関数呼び出し等がチェックされます。また実行時には隔離されたメモリ空間が与えられ、整数オーバーフローや範囲外参照が検知されます。このため、Wasmバイナリは安全に実行することができます。ただし、WasmOSはWasmにメッセージパッシング用のAPIを提供しています。マイクロカーネルではユーザー空間で動くサーバー群によって"OS"の機能が実現されるため、これは(何も制限を加えなければ)Wasmから全てのシステムコールを呼び出せることと同じです。アクセス制御を実装することが今後の課題ですが、重要なのは、アクセス制御の方法を**OSレベルで**考えられる点です。

私は、WasmとWASIが目指す[デフォルトでセキュアな世界](https://hacks.mozilla.org/2019/11/announcing-the-bytecode-alliance/)のためには、WASIのレベルではなく、OSのレベルでセキュリティを考えるべきだと思っています。WASIはセキュリティを考えて設計されていますが「使わない」という選択肢がある限り、ユーザーはセキュリティを考えて設計された"使いにくい"APIよりもより便利で、なんでもできるAPIを望むからです。

## Efficient
Wasmは上記のような特徴を持つため、カーネル空間でもある程度安全に実行することができます。WasmOSは全てのWasmバイナリをカーネル空間で実行します。システムコールが関数呼び出しになり、コンテキストスイッチが必要なくなるため、高速なマイクロカーネルを実現できる可能性があります。

# Related Projects
Wasm x Kernelはそこまで新しい話ではありません。例えば[Nebulet](https://github.com/nebulet/nebulet)はWasmOS同様、Wasmをカーネル空間で実行することで高速なマイクロカーネルを実装するプロジェクトです。他にもWasmランタイムをLinuxのカーネルモジュールとして動作させ、Wasmをカーネル空間で実行する[kernel-wasm](https://github.com/wasmerio/kernel-wasm)や、IoTデバイス上でWasmを実行することに特化した [Wasmachine](https://ieeexplore.ieee.org/document/9156135)というOSがあります。また、マイクロカーネル的なアプローチで分散システムを構築しているものとして、[wasmcloud](https://wasmcloud.com/)があります。

# 新しいOSを作ろう!
WasmOSは既存のOSやWASIを完全に置き換えるものではありません。既存の資産を活用するのは重要です。(私はこれがWASIがPOSIXに似たものになっている理由だと考えています)しかし、私たちはWasmとWASIをゼロから作っています。せっかく新しいものを作るなら、既存の技術にとらわれず、新しい道を考えてもよいでしょう。皆さんもぜひ自由な発想でWasmOSを拡張してみてください。(PR待ってます！)

# 参考
https://www.shuwasystem.co.jp/book/9784798068718.html

https://speakerdeck.com/nullpo_head/kanerukong-jian-desubetenopurosesuwodong-kasuniha-tal-sfi-wasmtoka

https://hacks.mozilla.org/2019/03/standardizing-wasi-a-webassembly-system-interface/

https://hacks.mozilla.org/2019/11/announcing-the-bytecode-alliance/

https://arxiv.org/abs/2312.03858

https://ieeexplore.ieee.org/document/9156135


https://zenn.dev/koduki/articles/9f86d03cd703c4


