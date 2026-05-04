;;; block-copyfail-elf.lisp — Compile block-copyfail to a .bpf.o ELF object
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Produces block-copyfail.bpf.o which can be loaded with bpftool:
;;;   sudo bpftool prog load block-copyfail.bpf.o /sys/fs/bpf/block_copyfail
;;;   sudo bpftool link attach pinned /sys/fs/bpf/block_copyfail lsm

(in-package #:whistler)

(defstruct salg-check
  (family u16)             ;  0: salg_family
  (type-0 u8)              ;  2: 'a'
  (type-1 u8)              ;  3: 'e'
  (type-2 u8)              ;  4: 'a'
  (type-3 u8)              ;  5: 'd'
  (type-4 u8))             ;  6: '\0'

(defstruct block-event
  (pid  u32)
  (comm (array u8 16))
  (ts   u64))

(defconstant +af-alg+ 38)

(defmap events :type :ringbuf :max-entries 4096)

(defprog block-aead (:type :lsm
                     :section "lsm/socket_bind"
                     :license "GPL")
  (let ((sc (make-salg-check)))
    (probe-read-kernel sc 7 (ctx u64 8))
    (if (and (= (salg-check-family sc) +af-alg+)
             (= (salg-check-type-0 sc) 97)    ; 'a'
             (= (salg-check-type-1 sc) 101)   ; 'e'
             (= (salg-check-type-2 sc) 97)    ; 'a'
             (= (salg-check-type-3 sc) 100)   ; 'd'
             (= (salg-check-type-4 sc) 0))
        (let ((evt (make-block-event)))
          (setf (block-event-pid evt)
                (cast u32 (>> (get-current-pid-tgid) 32)))
          (get-current-comm (block-event-comm-ptr evt) 16)
          (setf (block-event-ts evt) (ktime-get-ns))
          (ringbuf-output events evt (sizeof block-event) 0)
          (return -1))
        (return 0))))
