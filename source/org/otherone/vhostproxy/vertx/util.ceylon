import java.util.concurrent.locks {
    JReentrantLock=ReentrantLock
}

class ReentrantLock() satisfies Obtainable {
    JReentrantLock lock = JReentrantLock();
    shared actual void obtain() => lock.lockInterruptibly();
    shared actual void release(Throwable? error) => lock.unlock();
}

Anything() tc0(Anything() func) {
    return () {
        try {
            func();
        } catch (Throwable e) {
            log.error("Error", e);
        }
    };
}

Anything(T) tc<T>(Anything(T) func) {
    return (T t) {
        try {
            func(t);
        } catch (Throwable e) {
            log.error("Error", e);
        }
    };
}

