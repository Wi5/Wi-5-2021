patch_ath9k() {
  if ! [ -d odin-driver-patches ]; then
    git clone git://github.com/lalithsuresh/odin-driver-patches.git
  fi
  sed -e '1,2d' \
      -e 's/compat-wireless-2011-12-01.orig/a/' \
      -e 's/compat-wireless-2011-12-01/b/' \
      -e 's/ath9k_debugfs_open/simple_open/' \
    odin-driver-patches/ath9k/ath9k-bssid-mask.patch \
    > package/kernel/mac80211/patches/580-ath9k-bssid-mask.patch
}

patch_ath9k
