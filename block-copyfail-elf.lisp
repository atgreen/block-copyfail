;;; block-copyfail-elf.lisp — Compile block-copyfail to a .bpf.o ELF object
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Produces block-copyfail.bpf.o which can be loaded with bpftool:
;;;   sudo bpftool prog load block-copyfail.bpf.o /sys/fs/bpf/block_copyfail
;;;   sudo bpftool link attach pinned /sys/fs/bpf/block_copyfail lsm

(in-package #:whistler)

(defstruct salg-check
  (family u16)
  (pad    (array u8 22))
  (name-w0 u32)
  (name-w1 u32)
  (name-w2 u16))

(defstruct block-event
  (pid  u32)
  (comm (array u8 16))
  (ts   u64))

(defconstant +auth+ #x68747561)
(defconstant +ence+ #x65636e65)
(defconstant +sn+   #x6e73)
(defconstant +af-alg+ 38)

(defmap events :type :ringbuf :max-entries 4096)

(defprog block-authencesn (:type :lsm
                           :section "lsm/socket_bind"
                           :license "GPL")
  (let ((sc (make-salg-check)))
    (probe-read-kernel sc 34 (ctx u64 8))
    (if (and (= (salg-check-family sc) +af-alg+)
             (= (salg-check-name-w0 sc) +auth+)
             (= (salg-check-name-w1 sc) +ence+)
             (= (salg-check-name-w2 sc) +sn+))
        (let ((evt (make-block-event)))
          (setf (block-event-pid evt)
                (cast u32 (>> (get-current-pid-tgid) 32)))
          (get-current-comm (block-event-comm-ptr evt) 16)
          (setf (block-event-ts evt) (ktime-get-ns))
          (ringbuf-output events evt (sizeof block-event) 0)
          (return -1))
        (return 0))))
