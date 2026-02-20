import threading
import time
import traceback


class ExpiryEngine:
    def __init__(
        self,
        flow_manager,
        behavior_engine,
        volumetric_engine,
        block_manager,
        attack_session_manager,
        interval=5,
        debug=False
    ):
        self.flow_manager = flow_manager
        self.behavior_engine = behavior_engine
        self.volumetric_engine = volumetric_engine
        self.block_manager = block_manager
        self.attack_session_manager = attack_session_manager

        self.interval = interval
        self.debug = debug

        self._stop_event = threading.Event()
        self.thread = None

    # ---------------------------------------------------------
    # Start background expiry thread
    # ---------------------------------------------------------
    def start(self):
        if self.thread and self.thread.is_alive():
            return

        self._stop_event.clear()

        self.thread = threading.Thread(
            target=self._run,
            name="ExpiryEngineThread",
            daemon=True
        )
        self.thread.start()

        if self.debug:
            print("[EXPIRY] Expiry engine started.")

    # ---------------------------------------------------------
    # Stop thread gracefully
    # ---------------------------------------------------------
    def stop(self):
        if not self.thread:
            return

        if self.debug:
            print("[EXPIRY] Stopping expiry engine...")

        self._stop_event.set()
        self.thread.join(timeout=self.interval + 2)

        if self.debug:
            print("[EXPIRY] Expiry engine stopped.")

    # ---------------------------------------------------------
    # Main background loop
    # ---------------------------------------------------------
    def _run(self):
        while not self._stop_event.is_set():

            start_time = time.time()

            try:
                # Flow expiration
                self.flow_manager.expire_flows()

                # Behavior engine cleanup
                if self.behavior_engine:
                    self.behavior_engine.expire_sources()

                # Volumetric cleanup
                if self.volumetric_engine:
                    self.volumetric_engine.expire_sources()

                # Block expiration
                if self.block_manager:
                    self.block_manager.expire_blocks()

                if self.attack_session_manager:
                    self.attack_session_manager.expire_sessions()

                if self.debug:
                    print("[EXPIRY] Cleanup cycle completed.")

                

            except Exception as e:
                # Never allow expiry thread to crash IPS
                print("[EXPIRY ERROR] Exception during cleanup:")
                traceback.print_exc()

            # -------------------------------------------------
            # Maintain consistent interval timing
            # -------------------------------------------------
            elapsed = time.time() - start_time
            sleep_time = max(self.interval - elapsed, 0)

            self._stop_event.wait(sleep_time)
