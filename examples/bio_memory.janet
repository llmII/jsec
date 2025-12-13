(import jsec/bio)

(print "Creating a memory BIO...")
(with [mem-bio (bio/new-mem)]
  (print "Writing data to BIO...")
  (:write mem-bio "Hello, ")
  (:write mem-bio "BIO World!")

  (print "Reading all data from BIO...")
  (let [data (bio/to-string mem-bio)]
    (print "Read: " data)
    (assert (= data "Hello, BIO World!") "Data mismatch!"))

  (print "BIO automatically closed via 'with' macro"))

(print "BIO Memory example successful!")
