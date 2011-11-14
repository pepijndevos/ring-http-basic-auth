(ns ring.middleware.http-basic-auth
  "Ring middleware for basic HTTP authentication."
  (:import javax.xml.bind.DatatypeConverter)
  (:require [clojure.string :as s]))

(defn base64decode [string]
  (String. (DatatypeConverter/parseBase64Binary string)))

(defn credentials [req]
  (when-let [auth (get-in req [:headers "authorization"])]
    (let [cred (base64decode (subs auth 5))]
      (vec (s/split cred #":" 2)))))

(defn assoc-in*
  ([m ks v & kv]
   (apply assoc-in (assoc-in m ks v) kv))
  ([m [k & ks] v]
   (if ks
     (assoc m k (assoc-in (get m k) ks v))
     (assoc m k v))))

(defn challenge [resp realm]
  (assoc-in* resp
            [:status] 401
            [:headers "WWW-Authenticate"]
              (format "Basic realm=\"%s\"" realm)))

(defn wrap-basic-auth
  "RFC2617 Basic authenticator.
  Supply realm string and credentials validation fn.
  
  (if-let [username (:login req)]
    (str \"hi \" username)
    \"error\")"
  [handler realm user?]
  (fn [req]
    (let [[username password] (credentials req)]
      (if-let [status (user? username password)]
        (handler (assoc req :login status))
        (challenge (handler req) realm)))))
