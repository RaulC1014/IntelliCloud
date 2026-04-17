import { useEffect, useRef, useState, useCallback } from "react";
import { buildSseUrl } from "../api/http";

export default function useTrafficStream({
  path = "traffic/stream",
  enabled = true,
  maxRows = 500,
  flushMs = 50,
  storageKey = "ic_lastTrafficId",
  since: sinceProp = null,
  clientKey = null,
} = {}) {
  const [rows, setRows] = useState([]);
  const [connected, setConnected] = useState(false);
  const [lastId, setLastId] = useState(0);

  const esRef = useRef(null);
  const bufRef = useRef([]);
  const flushTimerRef = useRef(null);
  const lastIdRef = useRef(0);

  useEffect(() => {
    const saved = localStorage.getItem(storageKey);
    const n = saved != null ? Number(saved) : 0;
    const safe = Number.isFinite(n) ? n : 0;
    lastIdRef.current = safe;
    setLastId(safe);
  }, [storageKey]);

  const flush = useCallback(() => {
    flushTimerRef.current = null;
    const chunk = bufRef.current;
    bufRef.current = [];

    if (!chunk.length) return;

    setRows((prev) => {
      const next = [...chunk, ...prev];
      if (next.length > maxRows) next.length = maxRows;
      return next;
    });
  }, [maxRows]);

  const scheduleFlush = useCallback(() => {
    if (flushTimerRef.current) return;
    flushTimerRef.current = window.setTimeout(flush, flushMs);
  }, [flush, flushMs]);

  useEffect(() => {
    if (esRef.current) {
      try {
        esRef.current.close();
      } catch (error) {
        console.warn("useTrafficStream: failed to close previous EventSource", error);
      }
    }

    esRef.current = null;
    setConnected(false);

    if (!enabled) {
      if (bufRef.current.length) scheduleFlush();
      return;
    }

    if (!clientKey) {
      if (bufRef.current.length) scheduleFlush();
      return;
    }

    const since =
      sinceProp !== null && sinceProp !== undefined
        ? sinceProp
        : (lastIdRef.current || 0);

    const url = buildSseUrl(path, {
      since,
      client_key: clientKey,
    });

    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      setConnected(true);
    };

    es.onerror = () => {
      setConnected(false);
    };

    es.onmessage = (evt) => {
      if (evt.lastEventId) {
        const n = Number(evt.lastEventId);
        if (Number.isFinite(n)) {
          lastIdRef.current = n;
          setLastId(n);
          localStorage.setItem(storageKey, String(n));
        }
      }

      try {
        const data = JSON.parse(evt.data);

        if (data && data.id != null) {
          const n = Number(data.id);
          if (Number.isFinite(n)) {
            lastIdRef.current = n;
            setLastId(n);
            localStorage.setItem(storageKey, String(n));
          }
        }

        bufRef.current.push(data);
        scheduleFlush();
      } catch (error) {
        console.warn("useTrafficStream: failed to parse SSE payload", {
          error,
          rawData: evt?.data,
        });
      }
    };

    return () => {
      setConnected(false);

      if (esRef.current) {
        try {
          esRef.current.close();
        } catch (error) {
          console.warn("useTrafficStream: failed to close EventSource during cleanup", error);
        }
      }

      esRef.current = null;
    };
  }, [enabled, path, sinceProp, storageKey, clientKey, scheduleFlush]);

  const clear = useCallback(() => {
    setRows([]);
    bufRef.current = [];

    if (flushTimerRef.current) {
      clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
  }, []);

  const resetCursor = useCallback(() => {
    lastIdRef.current = 0;
    setLastId(0);
    localStorage.setItem(storageKey, "0");
  }, [storageKey]);

  return {
    rows,
    connected,
    lastId,
    clear,
    resetCursor,
  };
}