; Word operations used by actor membership and single-use record marking.
; The two machine widths have satisfiable premises, exact masks and a negative
; control that truncates bit positions to three bits.
(set-logic QF_BV)
(declare-const value (_ BitVec 32))
(declare-const index (_ BitVec 32))
(declare-const other (_ BitVec 32))
(assert (bvult index #x00000020))
(define-fun mask () (_ BitVec 32) (bvshl #x00000001 index))
; EXPECT: sat
(check-sat)
(push)
(assert (= mask #x00000000))
; EXPECT: unsat
(check-sat)
(pop)
(push)
(assert (= (bvand (bvor value mask) mask) #x00000000))
; EXPECT: unsat
(check-sat)
(pop)
(push)
(assert (not (= (bvand (bvor value mask) (bvnot mask)) (bvand value (bvnot mask)))))
; EXPECT: unsat
(check-sat)
(pop)
(assert (bvult other #x00000020))
(assert (not (= index other)))
; EXPECT: sat
(check-sat)
(push)
(assert (= mask (bvshl #x00000001 other)))
; EXPECT: unsat
(check-sat)
(pop)
(assert (bvuge index #x00000008))
(assert (= value #x00000000))
; EXPECT: sat
(check-sat)
(assert (= (bvand (bvor value (bvshl #x00000001 (bvand index #x00000007))) mask) #x00000000))
; EXPECT: sat
(check-sat)
(reset)
(set-logic QF_BV)
(declare-const value (_ BitVec 64))
(declare-const index (_ BitVec 64))
(declare-const other (_ BitVec 64))
(assert (bvult index #x0000000000000040))
(define-fun mask () (_ BitVec 64) (bvshl #x0000000000000001 index))
; EXPECT: sat
(check-sat)
(push)
(assert (= mask #x0000000000000000))
; EXPECT: unsat
(check-sat)
(pop)
(push)
(assert (= (bvand (bvor value mask) mask) #x0000000000000000))
; EXPECT: unsat
(check-sat)
(pop)
(push)
(assert (not (= (bvand (bvor value mask) (bvnot mask)) (bvand value (bvnot mask)))))
; EXPECT: unsat
(check-sat)
(pop)
(assert (bvult other #x0000000000000040))
(assert (not (= index other)))
; EXPECT: sat
(check-sat)
(push)
(assert (= mask (bvshl #x0000000000000001 other)))
; EXPECT: unsat
(check-sat)
(pop)
(assert (bvuge index #x0000000000000008))
(assert (= value #x0000000000000000))
; EXPECT: sat
(check-sat)
(assert (= (bvand (bvor value (bvshl #x0000000000000001 (bvand index #x0000000000000007))) mask) #x0000000000000000))
; EXPECT: sat
(check-sat)
