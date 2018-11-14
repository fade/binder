;; -*-lisp-*-
;;;; binder.asd

(asdf:defsystem #:binder
  :description "utilities to manipulate bind9 zones in bulk."
  :author "Brian O'Reilly <fade@deepsky.com>"
  :license "Modified BSD License"
  :serial t
  :depends-on (:cl-ppcre
               :rutils
               :alexandria
               :iolib
               :simple-date-time
               :net.didierverna.clon)
  :pathname "./"
  :components ((:file "app-utils")
               (:file "binder")))

