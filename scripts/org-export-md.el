;;; org-export-md.el --- Batch Org-to-Markdown exporter -*- lexical-binding: t; -*-

;; Exports Org documents to Markdown with deterministic anchor references:
;; headlines use GFM-style slugs (respecting explicit :CUSTOM_ID: properties)
;; and non-headline targets use sequential IDs rather than Org's default
;; random per-run hex suffixes (#orgXXXXXXX).

(require 'subr-x)
(require 'ox)
(require 'ox-md)

(setq make-backup-files nil)

(defun jsec-org-md--slugify (title)
  "Convert headline TITLE into a deterministic Markdown anchor slug."
  (let* ((lower (downcase (or title "")))
         (stripped (replace-regexp-in-string "[^a-z0-9 _-]" "" lower))
         (hyphened (replace-regexp-in-string "[ \t]+" "-" (string-trim stripped))))
    (setq hyphened (replace-regexp-in-string "-+" "-" hyphened))
    (setq hyphened (replace-regexp-in-string "\\`-+\\|-+\\'" "" hyphened))
    (if (string-empty-p hyphened) "section" hyphened)))

(defun jsec-org-export-get-reference (_orig-fn datum info)
  "Return a deterministic internal reference string for DATUM during export."
  (let* ((cache (plist-get info :internal-references))
         (existing (car (rassq datum cache))))
    (or existing
        (let* ((candidate
                (if (eq (org-element-type datum) 'headline)
                    (let* ((custom (org-element-property :CUSTOM_ID datum))
                           (raw-title (org-element-property :raw-value datum))
                           (base (if (org-string-nw-p custom)
                                     custom
                                   (jsec-org-md--slugify raw-title)))
                           (cand base)
                           (n 1))
                      (while (assoc cand cache)
                        (setq cand (format "%s-%d" base n))
                        (setq n (1+ n)))
                      cand)
                  (let ((n (1+ (length cache)))
                        (cand nil))
                    (setq cand (format "org-ref-%d" n))
                    (while (assoc cand cache)
                      (setq n (1+ n))
                      (setq cand (format "org-ref-%d" n)))
                    cand))))
          (push (cons candidate datum) cache)
          (plist-put info :internal-references cache)
          candidate))))

(advice-add 'org-export-get-reference :around #'jsec-org-export-get-reference)
