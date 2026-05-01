;;; block-copyfail.lisp — Block CVE-2026-31431 (Copy Fail) via BPF LSM
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Hooks lsm/socket_bind and blocks only AF_ALG binds that specify
;;; the "authencesn" algorithm — the specific template exploited by
;;; Copy Fail.  All other AF_ALG usage (dm-crypt, hash, skcipher, etc.)
;;; continues to work.
;;;
;;; Blocked attempts are reported to the console in real time via a
;;; ring buffer, showing PID, process name, and timestamp.
;;;
;;; Prerequisites:
;;;   - Linux kernel 5.7+ with CONFIG_BPF_LSM=y and lsm=bpf enabled
;;;   - CAP_BPF + CAP_MAC_ADMIN (or root)
;;;
;;; Usage:
;;;   sudo sbcl --load block-copyfail.lisp

(require "asdf")
(asdf:load-system "whistler")
(asdf:load-system "whistler/loader")

(in-package #:whistler-loader-user)

;;; struct sockaddr_alg layout:
;;;   offset  0: u16 salg_family
;;;   offset  2: u8[14] salg_type
;;;   offset 16: u32 salg_feat
;;;   offset 20: u32 salg_mask
;;;   offset 24: u8[64] salg_name

(whistler:defstruct salg-check
  (family u16)             ;  0: salg_family
  (pad    (array u8 22))   ;  2: skip type/feat/mask
  (name-w0 u32)            ; 24: "auth"
  (name-w1 u32)            ; 28: "ence"
  (name-w2 u16))           ; 32: "sn"

;;; Event struct sent to userspace via ring buffer
(whistler:defstruct block-event
  (pid  u32)               ;  0: blocking PID
  (comm (array u8 16))     ;  4: process name
  (ts   u64))              ; 24: ktime_ns timestamp (with padding at 20)

;; "authencesn" as little-endian words
(defconstant +auth+ #x68747561)
(defconstant +ence+ #x65636e65)
(defconstant +sn+   #x6e73)
(defconstant +af-alg+ 38)

(defun format-current-time ()
  "Format the current local wall-clock time as HH:MM:SS."
  (multiple-value-bind (second minute hour)
      (decode-universal-time (get-universal-time))
    (format nil "~2,'0d:~2,'0d:~2,'0d" hour minute second)))

(defun check-prerequisites ()
  "Check for root and BPF LSM support. Exit with a message on failure."
  (unless (zerop (sb-posix:getuid))
    (format *error-output* "Error: must run as root (or with CAP_BPF + CAP_MAC_ADMIN).~%")
    (sb-ext:exit :code 1))
  (let ((lsm-path "/sys/kernel/security/lsm"))
    (unless (and (probe-file lsm-path)
                 (search "bpf" (uiop:read-file-string lsm-path)))
      (format *error-output* "Error: BPF LSM not enabled.~%")
      (format *error-output* "Add lsm=bpf to your kernel boot parameters.~%")
      (sb-ext:exit :code 1))))

(defun run ()
  (check-prerequisites)
  (format *error-output* "Compiling BPF LSM program...~%")
  (with-bpf-session ()
    (bpf:map events :type :ringbuf :max-entries 4096)

    (bpf:prog block-authencesn (:type :lsm
                                :section "lsm/socket_bind"
                                :license "GPL")
      ;; socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
      (let ((sc (make-salg-check)))
        (probe-read-kernel sc 34 (ctx u64 8))
        (if (and (= (salg-check-family sc) +af-alg+)
                 (= (salg-check-name-w0 sc) +auth+)
                 (= (salg-check-name-w1 sc) +ence+)
                 (= (salg-check-name-w2 sc) +sn+))
            ;; Blocked — emit event, then return -EPERM
            (let ((evt (make-block-event)))
              (setf (block-event-pid evt)
                    (cast u32 (>> (get-current-pid-tgid) 32)))
              (get-current-comm (block-event-comm-ptr evt) 16)
              (setf (block-event-ts evt) (ktime-get-ns))
              (ringbuf-output events evt (sizeof block-event) 0)
              (return -1))
            (return 0))))

    (format *error-output* "Attaching to lsm/socket_bind...~%")
    (bpf:attach block-authencesn)

    (format t "~&Copy Fail blocker active — authencesn bind blocked.~%")
    (format t "Other AF_ALG usage (dm-crypt, hash, skcipher) unaffected.~%")
    (format t "Watching for blocked attempts. Press Ctrl-C to exit.~%~%")
    (format t "~20a  ~8a  ~a~%" "TIME" "PID" "COMMAND")
    (format t "~20a  ~8a  ~a~%" "----" "---" "-------")

    ;; Consume ring buffer events
    (let* ((events-map (bpf-session-map 'events))
           (consumer (open-decoding-ring-consumer
                      events-map
                      #'decode-block-event
                      (lambda (evt)
                        (let* ((comm-bytes (block-event-record-comm evt))
                               (end (or (position 0 comm-bytes) (length comm-bytes)))
                               (comm (map 'string #'code-char
                                          (subseq comm-bytes 0 end))))
                          (format t "~20a  ~8d  ~a~%"
                                  (format-current-time)
                                  (block-event-record-pid evt)
                                  comm)
                          (force-output))))))
      (unwind-protect
           (handler-case
               (loop (ring-poll consumer :timeout-ms 250))
             (sb-sys:interactive-interrupt ()
               (format t "~&~%Detaching blocker...~%")))
        (close-ring-consumer consumer))))

  (format t "Blocker removed.~%"))

(unless (member "--build" sb-ext:*posix-argv* :test #'string=)
  (run))
