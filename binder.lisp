;; -*-lisp-*-
(defpackage :binder
            (:use :cl)
            (:use :binder.app-utils)
            (:export :-main))

(in-package :binder)

(defparameter *bind-paths*
  (merge-pathnames (first (uiop:system-config-pathnames)) (user-homedir-pathname)))

(defclass secondary-zone-log (parents)
  ((log-path
    :initarg :log-path
    :initform nil
    :accessor log-path)
   (zone-objects
    :initarg :zone-objects
    :initform nil
    :accessor zone-objects))
  (:documentation "this object represents the zone log from a secondary bind server."))

;;===============================================================================
;; zone files and zone file component objects.
;;===============================================================================

(defconstant +a+ :a)
(defconstant +ns+ :ns)
(defconstant +mx+ :mx)
(defconstant +soa+ :soa)

(deftype z-record ()
  '(member +a+ +ns+ +mx+ +soa+))

(defclass zone-record ()
  ((kind
    :initarg :kind
    :initform nil
    :accessor kind)
   (name
    :initarg :name
    :initform nil
    :accessor name)
   (ipaddr
    :initarg :ipaddr
    :initform (error "must include an address record, because otherwise, what's the point?")
    :accessor ipaddr)))

(defclass a (zone-record)
  ((kind :initform +a+))
  (:documentation "a zone file A record."))

(defclass ns (zone-record)
  ((kind :initform +ns+))
  (:documentation "a zone file NS record"))

(defclass mx (zone-record)
  ((kind :initform +mx+))
  (:documentation "a zone file [M]ail[X]changer record"))

(defclass soa (zone-record)
  ((domain
    :initarg :domain
    :initform (error "A SOA without a domain does not make sense. Provide a domain.")
    :accessor domain)
   (start-of-authortity
    :initarg :start-of-authority
    :initform (error "A SOA by definition requires a host to stand for. Provide the authoritative DNS server.")
    :accessor start-of-authority)
   (serial
    :initarg :serial
    :initform (get-universal-time)
    :accessor serial)
   (refresh
    :initarg :refresh
    :initform 10800
    :accessor refresh-period)
   (retry
    :initarg :retry
    :initform 3600
    :accessor retry-period)
   (expiration
    :initarg :expiration
    :initform 302400
    :accessor expiration)
   (minimum
    :initarg :minimum
    :initform 86400
    :accessor :minimum-period)
   (kind :initform +soa+))
  (:documentation "a zone file [S]tart [O]f [A]uthority record"))

(defmethod initialize-instance :after ((zone zone-record) &key)
  ;; cut the raw data apart in here.
  (setf (ipaddr zone) (iolib.sockets:make-address (ipaddr zone))))

(defclass zone-object ()
  ((raw-data
    :initarg :raw-data
    :initform nil
    :accessor raw-data)
   (zone-soa
    :initarg :zone-soa
    :initform nil
    :accessor zone-soa)
   (zone-ns
    :initarg :zone-ns
    :initform nil
    :accessor zone-ns)
   (zone-a
    :initarg :zone-a
    :initform nil
    :accessor zone-a)
   (zone-mx
    :initarg :zone-mx
    :initform nil
    :accessor zone-mx)
   (zone-records
    :initarg :zone-records
    :initform nil
    :accessor zone-records
    :documentation "a list of zone record objects.")))

(defun read-bind-slave-log (file)
  "given the dumped db from a secondary nameserver, parse it and
  generate zones appropriate for a master bind9 node."
  (uiop:read-file-lines file))

(defun parse-bind-slave-log (lines)
  (let* ((ratchet nil)
         ;; ^\$ORIGIN\s+\w+\.\w+|^\$ORIGIN\s+\.
         (soareg (cl-ppcre:create-scanner "\w.\w\s*IN\s*SOA"))
         ;; (soaend (cl-ppcre:create-scanner ".*\)"))
         (record (cl-ppcre:create-scanner "(\s*[^SO]A\s*|INFO|TXT|HINFO|LOC|CNAME|^\$INCLUDE)"))
         (A      (cl-ppcre:create-scanner "(\s+A\s+)"))
         (ismx   (cl-ppcre:create-scanner "(MX)"))
         (isns   (cl-ppcre:create-scanner "(NS)"))
         (origin-top (cl-ppcre:create-scanner "(ORIGIN\s*[^\p]*\.)"))
         (origin-mid (cl-ppcre:create-scanner "(^\$ORIGIN\s+\w+\.\w+)"))
         soa-list
         ns-list
         mx-list
         red-list)
    (declare (ignorable ratchet soareg record ismx isns soa-list ns-list mx-list red-list a origin-top origin-mid))
    (loop for line in lines
          for count upfrom 1
          do (cond
               ;; ((search "ORIGIN" line :test #'string-equal) ;;(cl-ppcre:scan origin-top line)
               ;;  (let ((origin-top (cl-ppcre:scan-to-strings origin-top line)))
               ;;    (format t "~&[~05D] Type: ORIGIN-TOP ~S: ~A" count origin-top line)))
               ((cl-ppcre:scan origin-top line) ;; (search "ORIGIN" line :test #'string-equal)
                (let ((origin-top (cl-ppcre:scan-to-strings origin-top line)))
                  (format t "~&[~05D] Type: ORIGIN-TOP ~A: ~S" count origin-top line)))
               ;; ((cl-ppcre:scan origin-mid line)
               ;;  (let ((origin-mid (cl-ppcre:scan-to-strings origin-mid line)))
               ;;    (format t "~&[~05D] Type: ORIGIN-MID ~S: ~A" count origin-mid line)))
               ;; ((cl-ppcre:scan soareg line)
               ;;  (let ((soa (cl-ppcre:scan-to-strings soareg line)))
               ;;    (format t "~&[~05D] Type: ||SOA|| ~S: ~A" count soa line)))
               ((cl-ppcre:scan record line)
                (let ((record (cl-ppcre:scan-to-strings record line)))
                  (format t "~&[~05D] Type: REKKID ~A: ~S" count record line)))
               ;; ((cl-ppcre:scan A line)
               ;;  (let ((vatch (cl-ppcre:scan-to-strings A line)))
               ;;    (format t "~&[~05D] Type: BLONX ~A: ~S" count vatch line)))
               ;; ((cl-ppcre:scan ismx line)
               ;;  (format t "~&[~05D] ~A" count line))
               ;; ((cl-ppcre:scan isns line)
               ;;  (format t "~&[~05D] ~A" count line))
               ;; (t
               ;;  (format t "~&[~05D] No Match: ~A" count line))
               )
          )

    ;; (if (cl-ppcre:scan "\@+\W+IN\W+SOA" line)
    ;;                  (format t "~&[~05D] ~A" count line)
    ;;                  (format t "~&[~05D] No Line Matched SOA" count))

    (defun -main (&optional args)
      (format t "~a ~a~%" args "I don't do much yet"))))

